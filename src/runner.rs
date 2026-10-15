//! TOML-driven command, HTTP, and TCP verification.

use command_group::CommandGroup;
use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 64 * 1024;
const HTTP_BODY_LIMIT: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub commands: Vec<CommandCheck>,
    #[serde(default)]
    pub http: Vec<HttpCheck>,
    #[serde(default)]
    pub tcp: Vec<TcpCheck>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandCheck {
    pub name: String,
    pub group: String,
    pub component: Option<String>,
    #[serde(default = "unit_suite")]
    pub suite: String,
    #[serde(default = "dot")]
    pub cwd: String,
    pub argv: Vec<String>,
    #[serde(default = "command_timeout")]
    pub timeout: u64,
    pub coverage_file: Option<String>,
    pub minimum_coverage: Option<f64>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpCheck {
    pub name: String,
    pub group: String,
    pub component: Option<String>,
    #[serde(default = "network_suite")]
    pub suite: String,
    pub url: String,
    pub status: u16,
    pub body_contains: Option<String>,
    #[serde(default = "network_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpCheck {
    pub name: String,
    pub group: String,
    pub component: Option<String>,
    #[serde(default = "network_suite")]
    pub suite: String,
    pub host: String,
    pub port: u16,
    #[serde(default = "network_timeout")]
    pub timeout: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub group: Option<String>,
    pub component: Option<String>,
    pub suite: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub group: String,
    pub component: Option<String>,
    pub suite: String,
    pub passed: bool,
    pub seconds: f64,
    pub detail: String,
    pub coverage: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub seconds: f64,
    pub results: Vec<CheckResult>,
}

fn unit_suite() -> String {
    "unit".into()
}
fn network_suite() -> String {
    "network".into()
}
fn dot() -> String {
    ".".into()
}
fn command_timeout() -> u64 {
    300
}
fn network_timeout() -> u64 {
    10
}

pub fn load(path: &Path) -> Result<Config, String> {
    let source = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let config: Config = toml::from_str(&source).map_err(|e| format!("invalid TOML: {e}"))?;
    validate(&config)?;
    Ok(config)
}

fn validate(config: &Config) -> Result<(), String> {
    if config.commands.is_empty() && config.http.is_empty() && config.tcp.is_empty() {
        return Err("profile must contain at least one check".into());
    }
    let mut names = HashSet::new();
    for check in &config.commands {
        common(
            &mut names,
            &check.name,
            &check.group,
            &check.suite,
            check.timeout,
        )?;
        if check.argv.is_empty() || check.argv.iter().any(String::is_empty) {
            return Err(format!("{} requires a non-empty argv", check.name));
        }
        if check
            .minimum_coverage
            .is_some_and(|v| check.coverage_file.is_none() || !(0.0..=100.0).contains(&v))
        {
            return Err(format!("{} has an invalid minimum_coverage", check.name));
        }
        if check
            .env
            .keys()
            .any(|key| key.is_empty() || key.contains('=') || key.contains('\0'))
        {
            return Err(format!("{} has an invalid environment key", check.name));
        }
    }
    for check in &config.http {
        common(
            &mut names,
            &check.name,
            &check.group,
            &check.suite,
            check.timeout,
        )?;
        let url =
            Url::parse(&check.url).map_err(|e| format!("{} has invalid URL: {e}", check.name))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(format!(
                "{} requires an HTTP(S) URL without credentials",
                check.name
            ));
        }
        if !(100..=599).contains(&check.status) {
            return Err(format!("{} has invalid status", check.name));
        }
    }
    for check in &config.tcp {
        common(
            &mut names,
            &check.name,
            &check.group,
            &check.suite,
            check.timeout,
        )?;
        if check.host.trim().is_empty() || check.port == 0 {
            return Err(format!("{} has invalid TCP target", check.name));
        }
    }
    Ok(())
}

fn common(
    names: &mut HashSet<String>,
    name: &str,
    group: &str,
    suite: &str,
    timeout: u64,
) -> Result<(), String> {
    if name.trim().is_empty() || group.trim().is_empty() || suite.trim().is_empty() {
        return Err("check name, group, and suite cannot be empty".into());
    }
    if !(1..=86_400).contains(&timeout) {
        return Err(format!(
            "{name} timeout must be between 1 and 86400 seconds"
        ));
    }
    if !names.insert(name.into()) {
        return Err(format!("duplicate check name: {name}"));
    }
    Ok(())
}

pub fn selections(config: &Config) -> Vec<Filter> {
    let mut values = Vec::new();
    let mut seen = HashSet::new();
    let metadata = config
        .commands
        .iter()
        .map(|c| (&c.group, &c.component, &c.suite))
        .chain(
            config
                .http
                .iter()
                .map(|c| (&c.group, &c.component, &c.suite)),
        )
        .chain(
            config
                .tcp
                .iter()
                .map(|c| (&c.group, &c.component, &c.suite)),
        );
    for (group, component, suite) in metadata {
        for candidate in [
            Filter {
                group: Some(group.clone()),
                component: None,
                suite: None,
            },
            Filter {
                group: Some(group.clone()),
                component: component.clone(),
                suite: None,
            },
            Filter {
                group: Some(group.clone()),
                component: component.clone(),
                suite: Some(suite.clone()),
            },
        ] {
            if seen.insert((
                candidate.group.clone(),
                candidate.component.clone(),
                candidate.suite.clone(),
            )) {
                values.push(candidate);
            }
        }
    }
    values
}

fn selected(group: &str, component: Option<&str>, suite: &str, filter: &Filter) -> bool {
    filter.group.as_deref().is_none_or(|v| v == group)
        && filter
            .component
            .as_deref()
            .is_none_or(|v| Some(v) == component)
        && filter.suite.as_deref().is_none_or(|v| v == suite)
}

pub fn run(config_path: &Path, filter: &Filter) -> Result<Report, String> {
    let config = load(config_path)?;
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    let mut results = Vec::new();
    for check in &config.commands {
        if selected(
            &check.group,
            check.component.as_deref(),
            &check.suite,
            filter,
        ) {
            results.push(run_command(check, base));
        }
    }
    for check in &config.http {
        if selected(
            &check.group,
            check.component.as_deref(),
            &check.suite,
            filter,
        ) {
            results.push(run_http(check));
        }
    }
    for check in &config.tcp {
        if selected(
            &check.group,
            check.component.as_deref(),
            &check.suite,
            filter,
        ) {
            results.push(run_tcp(check));
        }
    }
    if results.is_empty() {
        return Err("no checks matched the selected filters".into());
    }
    let passed = results.iter().filter(|r| r.passed).count();
    Ok(Report {
        total: results.len(),
        passed,
        failed: results.len() - passed,
        seconds: results.iter().map(|r| r.seconds).sum(),
        results,
    })
}

fn result(
    name: &str,
    group: &str,
    component: &Option<String>,
    suite: &str,
    started: Instant,
    outcome: Result<Option<f64>, String>,
) -> CheckResult {
    let (passed, detail, coverage) = match outcome {
        Ok(coverage) => (true, String::new(), coverage),
        Err(error) => (false, error, None),
    };
    CheckResult {
        name: name.into(),
        group: group.into(),
        component: component.clone(),
        suite: suite.into(),
        passed,
        seconds: started.elapsed().as_secs_f64(),
        detail,
        coverage,
    }
}

fn read_bounded(mut stream: impl Read, tx: mpsc::Sender<(Vec<u8>, bool)>) {
    let mut output = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                let _ = tx.send((output, false));
                return;
            }
            Ok(n) => {
                if n > OUTPUT_LIMIT - output.len() {
                    output.extend_from_slice(&buf[..OUTPUT_LIMIT - output.len()]);
                    let _ = tx.send((output, true));
                    return;
                }
                output.extend_from_slice(&buf[..n]);
            }
            Err(_) => {
                let _ = tx.send((output, true));
                return;
            }
        }
    }
}

fn stop_group(mut child: command_group::GroupChild) -> Option<String> {
    let error = child.kill().err().map(|e| e.to_string());
    // Reap without allowing pipe-drain or termination delays to exceed the check deadline.
    thread::spawn(move || {
        let _ = child.wait();
    });
    error
}

fn run_command(check: &CommandCheck, base: &Path) -> CheckResult {
    let started = Instant::now();
    let outcome = (|| -> Result<Option<f64>, String> {
        let cwd = base.join(&check.cwd);
        if !cwd.is_dir() {
            return Err(format!("working directory not found: {}", cwd.display()));
        }
        let mut command = Command::new(&check.argv[0]);
        command
            .args(&check.argv[1..])
            .current_dir(&cwd)
            .envs(&check.env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .group_spawn()
            .map_err(|e| format!("cannot start {}: {e}", check.argv[0]))?;
        let (tx, rx) = mpsc::channel();
        let stdout = child.inner().stdout.take().ok_or("cannot capture stdout")?;
        let stderr = child.inner().stderr.take().ok_or("cannot capture stderr")?;
        let stdout_tx = tx.clone();
        thread::spawn(move || read_bounded(stdout, stdout_tx));
        let stderr_tx = tx.clone();
        thread::spawn(move || read_bounded(stderr, stderr_tx));
        drop(tx);
        let deadline = started + Duration::from_secs(check.timeout);
        let mut streams = Vec::new();
        let mut status = None;
        loop {
            while let Ok(item) = rx.try_recv() {
                if item.1 {
                    let error = stop_group(child);
                    return Err(format!(
                        "command output exceeded {OUTPUT_LIMIT} bytes per stream{}",
                        error
                            .map(|e| format!("; failed to stop process group: {e}"))
                            .unwrap_or_default()
                    ));
                }
                streams.push(item.0);
            }
            if status.is_none() {
                status = match child.try_wait() {
                    Ok(status) => status,
                    Err(error) => {
                        let _ = stop_group(child);
                        return Err(format!("cannot wait for command: {error}"));
                    }
                };
                if status.is_some() {
                    // Stop descendants before waiting for inherited output handles to close.
                    let _ = child.kill();
                }
            }
            if status.is_some() && streams.len() == 2 {
                break;
            }
            if Instant::now() >= deadline {
                let error = stop_group(child);
                return Err(format!(
                    "timed out after {}s{}",
                    check.timeout,
                    error
                        .map(|e| format!("; failed to stop process group: {e}"))
                        .unwrap_or_default()
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
        // The leader may exit after starting descendants that close their output pipes.
        let _ = stop_group(child);
        let status = status.expect("checked above");
        if !status.success() {
            return Err(format!("command failed with status {status}"));
        }
        if let Some(relative) = &check.coverage_file {
            let path = safe_child(&cwd, relative)?;
            let coverage = read_lcov(&path)?;
            if let Some(minimum) = check.minimum_coverage
                && coverage < minimum
            {
                return Err(format!("coverage {coverage:.2}% is below {minimum:.2}%"));
            }
            Ok(Some(coverage))
        } else {
            Ok(None)
        }
    })();
    result(
        &check.name,
        &check.group,
        &check.component,
        &check.suite,
        started,
        outcome,
    )
}

fn run_http(check: &HttpCheck) -> CheckResult {
    let started = Instant::now();
    let outcome = (|| -> Result<Option<f64>, String> {
        let client = Client::builder()
            .timeout(Duration::from_secs(check.timeout))
            .redirect(Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        let mut response = client.get(&check.url).send().map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        if status != check.status {
            return Err(format!("expected HTTP {}, got {status}", check.status));
        }
        if let Some(needle) = &check.body_contains {
            let mut body = Vec::new();
            response
                .by_ref()
                .take((HTTP_BODY_LIMIT + 1) as u64)
                .read_to_end(&mut body)
                .map_err(|e| e.to_string())?;
            if body.len() > HTTP_BODY_LIMIT {
                return Err(format!("HTTP body exceeded {HTTP_BODY_LIMIT} bytes"));
            }
            if !String::from_utf8_lossy(&body).contains(needle) {
                return Err("response did not contain the required text".into());
            }
        }
        Ok(None)
    })();
    result(
        &check.name,
        &check.group,
        &check.component,
        &check.suite,
        started,
        outcome,
    )
}

fn run_tcp(check: &TcpCheck) -> CheckResult {
    let started = Instant::now();
    let timeout = Duration::from_secs(check.timeout);
    let host = check.host.clone();
    let port = check.port;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(
            (host.as_str(), port)
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<_>>()),
        );
    });
    let outcome = (|| -> Result<Option<f64>, String> {
        let addresses = rx
            .recv_timeout(timeout)
            .map_err(|_| "TCP resolution timed out".to_string())?
            .map_err(|e| e.to_string())?;
        if addresses.is_empty() {
            return Err("host resolved to no addresses".into());
        }
        let mut last_error = String::new();
        for address in addresses {
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err("TCP connection timed out".into());
            }
            match TcpStream::connect_timeout(&address, remaining) {
                Ok(_) => return Ok(None),
                Err(e) => last_error = e.to_string(),
            }
        }
        Err(last_error)
    })();
    result(
        &check.name,
        &check.group,
        &check.component,
        &check.suite,
        started,
        outcome,
    )
}

fn read_lcov(path: &Path) -> Result<f64, String> {
    let source =
        fs::read_to_string(path).map_err(|e| format!("coverage report {}: {e}", path.display()))?;
    let (mut found, mut hit) = (0_u64, 0_u64);
    for line in source.lines() {
        if let Some(v) = line.strip_prefix("LF:") {
            found = found
                .checked_add(v.parse::<u64>().map_err(|_| "invalid LCOV LF")?)
                .ok_or("LCOV overflow")?;
        }
        if let Some(v) = line.strip_prefix("LH:") {
            hit = hit
                .checked_add(v.parse::<u64>().map_err(|_| "invalid LCOV LH")?)
                .ok_or("LCOV overflow")?;
        }
    }
    if found == 0 || hit > found {
        return Err("invalid or empty LCOV report".into());
    }
    Ok(hit as f64 * 100.0 / found as f64)
}

fn safe_child(base: &Path, relative: &str) -> Result<PathBuf, String> {
    let base = base.canonicalize().map_err(|e| e.to_string())?;
    let path = base
        .join(relative)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if !path.starts_with(&base) {
        return Err("coverage_file must stay inside the check working directory".into());
    }
    Ok(path)
}

pub fn write_report(path: &Path, report: &Report) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    writeln!(file, "{json}").map_err(|e| e.to_string())
}
