# Veriv Toolkit

Veriv Toolkit is a modified public edition of a private verification toolkit built by Shafwan Taqiyuddin Abror. It runs command, HTTP, and TCP checks from TOML profiles. Examples use synthetic local targets; application profiles and internal findings remain private.

## Run locally

Install Rust 1.98.0 or let rustup use the pinned `rust-toolchain.toml`, then run:

```sh
git clone https://github.com/WaannAlter/veriv-toolkit.git
cd veriv-toolkit
cargo run --locked -- run --config checks.example.toml --list
cargo run -- run --config checks.example.toml --report reports/example.json
cargo test
```

`run` accepts `--group`, `--component`, and `--suite` filters. A selection with no matching checks is an error. A failed check exits with code 1; configuration or runner errors exit with code 2. The JSON report records each check's status, duration, optional coverage percentage, and failure detail. Reports are created only at new paths; an existing file or symlink is never overwritten. On Unix, new report files are owner-only (`0600`).

The optional `examples/hello.toml` profile checks the health endpoint of a service already running on loopback port 8080. It also works with the synthetic service in the [public Unified DevOps Tool edition](https://github.com/WaannAlter/unified-devops-tool):

```sh
cargo run --locked -- run --config examples/hello.toml
```

The runner is tested locally on Windows. Linux and macOS execution still need verification.

Define checks in a TOML file:

```toml
[[commands]]
name = "unit tests"
group = "app"
component = "core"
suite = "unit"
argv = ["cargo", "test"]
timeout = 300
# cwd = "."                 # relative to this profile
# coverage_file = "lcov.info" # relative to cwd
# minimum_coverage = 80.0

[[http]]
name = "readiness"
group = "app"
url = "http://127.0.0.1:8080/ready"
status = 200
body_contains = "ready"
timeout = 10

[[tcp]]
name = "service port"
group = "app"
host = "127.0.0.1"
port = 8080
timeout = 10
```

Profiles are trusted input, not a sandbox: commands run with the caller's access, and network checks contact the configured targets. Review profiles before running them. Timeouts range from 1 to 86400 seconds. Commands exceeding 64 KiB on either output stream fail; an HTTP body searched by `body_contains` is capped at 1 MiB. Failed command stdout and stderr are omitted from failure details; other check details and profile-supplied names may still be sensitive, so protect reports accordingly. HTTP redirects are not followed and credential-bearing URLs are rejected.

See [ROADMAP.md](ROADMAP.md) for the deliberately limited scope.

Licensed under [MIT](LICENSE). Copyright (c) 2026 Shafwan Taqiyuddin Abror.
