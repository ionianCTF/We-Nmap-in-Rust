//! End-to-end CLI tests: run the built `wnr` binary and check its output for
//! the subcommands that don't require a live network or capture device.

use std::process::Command;

fn wnr() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wnr"))
}

fn run(args: &[&str]) -> (String, String, i32) {
    let out = wnr().args(args).output().expect("spawn wnr");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn version_prints_name_and_version() {
    let (stdout, _, _) = run(&["--version"]);
    assert!(stdout.contains("WNR"), "got: {}", stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "got: {}", stdout);
}

#[test]
fn help_lists_commands() {
    let (stdout, _, _) = run(&["--help"]);
    for cmd in ["--interfaces", "--scan", "--pcap", "--route", "--version"] {
        assert!(stdout.contains(cmd), "missing '{}' in help: {}", cmd, stdout);
    }
}

#[test]
fn unknown_command_reports_error() {
    let (_, stderr, code) = run(&["--bogus"]);
    assert_eq!(code, 0);
    assert!(stderr.contains("unknown command"), "got: {}", stderr);
}

#[test]
fn scan_without_host_reports_error() {
    let (_, stderr, _) = run(&["--scan"]);
    assert!(stderr.contains("no host"), "got: {}", stderr);
}

#[test]
fn route_to_literal_localhost_succeeds() {
    // Resolving the loopback and querying the route should terminate either
    // with a route line or a "no route" line — never a panic or silent hang.
    let (stdout, _, _) = run(&["--route", "127.0.0.1"]);
    assert!(
        stdout.contains("route") || stdout.contains("no route"),
        "got: {}",
        stdout
    );
}
