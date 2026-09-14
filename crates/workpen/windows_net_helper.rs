//! Unique-PE wrap helper for Windows network deny. Compiled by build.rs only.

use std::env;
use std::ffi::OsString;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _argv0 = args.next();
    let rest: Vec<OsString> = args.collect();
    let Some(dash) = rest.iter().position(|a| a == "--") else {
        eprintln!("workpen-net-helper: missing --");
        return ExitCode::from(2);
    };
    let cmd = &rest[dash + 1..];
    if cmd.is_empty() {
        eprintln!("workpen-net-helper: empty command");
        return ExitCode::from(2);
    }
    let mut child = Command::new(&cmd[0]);
    if cmd.len() > 1 {
        child.args(&cmd[1..]);
    }
    match child.status() {
        Ok(st) => std::process::exit(st.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("workpen-net-helper: spawn {}: {e}", cmd[0].to_string_lossy());
            ExitCode::from(1)
        }
    }
}
