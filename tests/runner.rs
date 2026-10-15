use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use veriv_toolkit::runner::{self, Filter};

fn temp_profile(source: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("veriv-public-{}-{}", std::process::id(), rand_id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("checks.toml");
    fs::write(&path, source).unwrap();
    path
}

fn rand_id() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn command_profile(mode: &str, timeout: u64, extra: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let argv = [
        exe.to_string_lossy().to_string(),
        "--exact".into(),
        "fixture_process".into(),
        "--nocapture".into(),
    ];
    let argv = serde_json::to_string(&argv).unwrap();
    temp_profile(&format!(
        "[[commands]]\nname='fixture'\ngroup='g'\ncomponent='c'\nsuite='s'\nargv={argv}\ntimeout={timeout}\nenv={{ VERIV_FIXTURE_MODE='{mode}' }}\n{extra}\n"
    ))
}

#[test]
#[allow(clippy::zombie_processes)] // This fixture intentionally exits while its descendant holds inherited pipes.
fn fixture_process() {
    let Ok(mode) = std::env::var("VERIV_FIXTURE_MODE") else {
        return;
    };
    match mode.as_str() {
        "pass" => println!("passed"),
        "fail" => {
            eprintln!("synthetic failure");
            std::process::exit(7);
        }
        "timeout" => thread::sleep(Duration::from_secs(5)),
        "flood" => print!("{}", "x".repeat(128 * 1024)),
        "descendant" | "background" => {
            let marker = std::env::var("VERIV_MARKER").unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap());
            child
                .args(["--exact", "fixture_process", "--nocapture"])
                .env("VERIV_FIXTURE_MODE", "marker")
                .env("VERIV_MARKER", marker);
            if mode == "background" {
                child
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
            }
            child.spawn().unwrap();
        }
        "marker" => {
            thread::sleep(Duration::from_secs(2));
            fs::write(std::env::var("VERIV_MARKER").unwrap(), "orphan").unwrap();
        }
        _ => panic!("unknown fixture mode"),
    }
}

#[test]
fn command_pass_failure_filters_and_report() {
    let pass = command_profile("pass", 3, "");
    let report = runner::run(&pass, &Filter::default()).unwrap();
    assert_eq!((report.total, report.passed), (1, 1));
    let json = pass.with_file_name("report.json");
    runner::write_report(&json, &report).unwrap();
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(json).unwrap()).unwrap();
    assert_eq!(value["results"][0]["passed"], true);
    assert!(
        runner::run(
            &pass,
            &Filter {
                group: Some("other".into()),
                ..Default::default()
            }
        )
        .unwrap_err()
        .contains("no checks")
    );
    assert_eq!(runner::selections(&runner::load(&pass).unwrap()).len(), 3);
    let cli = Command::new(env!("CARGO_BIN_EXE_veriv-toolkit"))
        .args(["run", "--config", pass.to_str().unwrap(), "--list"])
        .output()
        .unwrap();
    assert!(cli.status.success());
    assert!(String::from_utf8_lossy(&cli.stdout).contains("g/c [s]"));
    let unmatched = Command::new(env!("CARGO_BIN_EXE_veriv-toolkit"))
        .args([
            "run",
            "--config",
            pass.to_str().unwrap(),
            "--group",
            "absent",
        ])
        .output()
        .unwrap();
    assert_eq!(unmatched.status.code(), Some(2));

    let fail = command_profile("fail", 3, "");
    let report = runner::run(&fail, &Filter::default()).unwrap();
    assert_eq!(report.failed, 1);
    assert!(report.results[0].detail.contains("synthetic failure"));
}

#[test]
fn timeout_output_cap_and_descendant_cleanup() {
    let timeout = command_profile("timeout", 1, "");
    let started = Instant::now();
    assert!(
        runner::run(&timeout, &Filter::default()).unwrap().results[0]
            .detail
            .contains("timed out")
    );
    assert!(started.elapsed() < Duration::from_secs(4));
    let flood = command_profile("flood", 3, "");
    assert!(
        runner::run(&flood, &Filter::default()).unwrap().results[0]
            .detail
            .contains("output exceeded")
    );

    let marker = std::env::temp_dir().join(format!("veriv-marker-{}", rand_id()));
    let descendant = command_profile("descendant", 1, "# marker\n");
    let mut text = fs::read_to_string(&descendant).unwrap();
    text.push_str(&format!("# marker path: {}\n", marker.display()));
    text = text.replace(
        "VERIV_FIXTURE_MODE='descendant'",
        &format!(
            "VERIV_FIXTURE_MODE='descendant', VERIV_MARKER={}",
            toml::Value::String(marker.to_string_lossy().to_string())
        ),
    );
    fs::write(&descendant, text).unwrap();
    let report = runner::run(&descendant, &Filter::default()).unwrap();
    assert_eq!(report.passed, 1, "{:?}", report.results);
    thread::sleep(Duration::from_secs(2));
    assert!(!marker.exists(), "descendant survived timeout");
}

#[test]
fn coverage_validation_and_strict_config() {
    let profile = command_profile(
        "pass",
        3,
        "coverage_file='coverage.lcov'\nminimum_coverage=75",
    );
    fs::write(profile.with_file_name("coverage.lcov"), "LF:4\nLH:3\n").unwrap();
    assert_eq!(
        runner::run(&profile, &Filter::default()).unwrap().results[0].coverage,
        Some(75.0)
    );
    fs::write(profile.with_file_name("coverage.lcov"), "LF:4\nLH:2\n").unwrap();
    assert_eq!(runner::run(&profile, &Filter::default()).unwrap().failed, 1);
    assert!(
        runner::load(&temp_profile(
            "[[commands]]\nname='x'\ngroup='g'\nargv=['cargo']\ntimeout=0\n"
        ))
        .is_err()
    );
    assert!(
        runner::load(&temp_profile(
            "[[commands]]\nname='x'\ngroup='g'\nargv=['cargo']\npostgres_image='private'\n"
        ))
        .is_err()
    );
}

#[test]
fn loopback_http_and_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0_u8; 1024];
        let _ = stream.read(&mut buf);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nready")
            .unwrap();
    });
    let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    let profile = temp_profile(&format!(
        "[[http]]\nname='http'\ngroup='g'\nurl='http://127.0.0.1:{port}/ready'\nstatus=200\nbody_contains='ready'\n[[tcp]]\nname='tcp'\ngroup='g'\nhost='127.0.0.1'\nport={tcp_port}\n"
    ));
    let report = runner::run(&profile, &Filter::default()).unwrap();
    assert_eq!((report.total, report.passed), (2, 2));
    server.join().unwrap();
    drop(tcp_listener);
    assert!(
        runner::load(&temp_profile(
            "[[http]]\nname='x'\ngroup='g'\nurl='http://user:password@127.0.0.1/'\nstatus=200\n"
        ))
        .is_err()
    );
}

#[test]
fn empty_profiles_and_excessive_timeouts_are_errors() {
    let empty = temp_profile("");
    assert!(runner::load(&empty).unwrap_err().contains("at least one"));
    let list = Command::new(env!("CARGO_BIN_EXE_veriv-toolkit"))
        .args(["run", "--config", empty.to_str().unwrap(), "--list"])
        .output()
        .unwrap();
    assert_eq!(list.status.code(), Some(2));
    assert!(runner::load(&command_profile("pass", 86_401, "")).is_err());
}

#[test]
fn successful_leader_does_not_leave_background_descendants() {
    let marker = std::env::temp_dir().join(format!("veriv-background-{}", rand_id()));
    let profile = command_profile("background", 3, "");
    let source = fs::read_to_string(&profile).unwrap().replace(
        "VERIV_FIXTURE_MODE='background'",
        &format!(
            "VERIV_FIXTURE_MODE='background', VERIV_MARKER={}",
            toml::Value::String(marker.to_string_lossy().to_string())
        ),
    );
    fs::write(&profile, source).unwrap();
    let report = runner::run(&profile, &Filter::default()).unwrap();
    assert_eq!(report.passed, 1, "{:?}", report.results);
    thread::sleep(Duration::from_millis(2300));
    assert!(
        !marker.exists(),
        "background descendant survived its completed check"
    );
}
