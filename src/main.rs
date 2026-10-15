use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::ExitCode;
use veriv_toolkit::runner::{self, Filter};

fn main() -> ExitCode {
    match execute(std::env::args().skip(1).collect()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::from(2)
        }
    }
}

fn execute(arguments: Vec<String>) -> Result<bool, String> {
    let mut args: VecDeque<String> = arguments.into();
    let command = args.pop_front().unwrap_or_else(|| "run".into());
    if matches!(command.as_str(), "help" | "--help" | "-h") {
        println!(
            "veriv-toolkit run [--config FILE] [--group NAME] [--component NAME] [--suite NAME] [--report FILE] [--list]"
        );
        return Ok(true);
    }
    if matches!(command.as_str(), "version" | "--version" | "-V") {
        println!("veriv-toolkit {}", env!("CARGO_PKG_VERSION"));
        return Ok(true);
    }
    if command != "run" {
        if command.starts_with('-') {
            args.push_front(command);
        } else {
            return Err(format!("unknown command {command:?}"));
        }
    }
    let mut config = PathBuf::from("checks.toml");
    let mut filter = Filter::default();
    let mut report_path = None;
    let mut list = false;
    while let Some(flag) = args.pop_front() {
        match flag.as_str() {
            "--config" => config = PathBuf::from(value(&mut args, &flag)?),
            "--group" => filter.group = Some(value(&mut args, &flag)?),
            "--component" => filter.component = Some(value(&mut args, &flag)?),
            "--suite" => filter.suite = Some(value(&mut args, &flag)?),
            "--report" => report_path = Some(PathBuf::from(value(&mut args, &flag)?)),
            "--list" => list = true,
            _ => return Err(format!("unknown run option {flag:?}")),
        }
    }
    if list {
        for selection in runner::selections(&runner::load(&config)?) {
            println!(
                "{}{}{}",
                selection.group.as_deref().unwrap_or("all"),
                selection
                    .component
                    .as_deref()
                    .map(|s| format!("/{s}"))
                    .unwrap_or_default(),
                selection
                    .suite
                    .as_deref()
                    .map(|s| format!(" [{s}]"))
                    .unwrap_or_default()
            );
        }
        return Ok(true);
    }
    let report = runner::run(&config, &filter)?;
    for item in &report.results {
        println!(
            "{} [{}/{}] {} ({:.2}s){}",
            if item.passed { "PASS" } else { "FAIL" },
            item.group,
            item.suite,
            item.name,
            item.seconds,
            item.coverage
                .map(|v| format!(" coverage={v:.2}%"))
                .unwrap_or_default()
        );
        if !item.detail.is_empty() {
            println!("{}", item.detail);
        }
    }
    println!(
        "{}/{} checks passed in {:.2}s",
        report.passed, report.total, report.seconds
    );
    if let Some(path) = report_path {
        runner::write_report(&path, &report)?;
    }
    Ok(report.failed == 0)
}

fn value(args: &mut VecDeque<String>, flag: &str) -> Result<String, String> {
    args.pop_front()
        .filter(|v| !v.is_empty() && !v.starts_with("--"))
        .ok_or_else(|| format!("{flag} requires a value"))
}
