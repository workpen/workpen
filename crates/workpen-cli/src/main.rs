//! workpen CLI. Wrap, explain, leftover GC.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime};

use workpen::{
    DenyPolicy, GcPolicy, PathGuard, explain, gc_leftovers, reject_command_secret_path_tokens,
};

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
    }
}

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    if args.is_empty() {
        eprintln!("Not ready.");
        return Ok(ExitCode::SUCCESS);
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("{}", workpen::VERSION);
        return Ok(ExitCode::SUCCESS);
    }
    match args[0].as_str() {
        "why" => cmd_why(&args[1..]),
        "run" => cmd_run(&args[1..]),
        "gc" => cmd_gc(&args[1..]),
        other => Err(format!("unknown command: {other}")),
    }
}

fn cmd_why(args: &[String]) -> Result<ExitCode, String> {
    let (root, extras, rest) = parse_roots(args)?;
    let path = rest
        .first()
        .ok_or_else(|| "usage: workpen why [--root DIR] [--extra-root DIR] PATH".to_string())?;
    let guard = PathGuard::with_extra_roots(&root, &extras).ok();
    let why = explain(Path::new(path), &DenyPolicy::default(), guard.as_ref());
    println!("{}", why.message());
    Ok(if matches!(why, workpen::Why::Allowed) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn cmd_run(args: &[String]) -> Result<ExitCode, String> {
    let (root, extras, rest) = parse_roots(args)?;
    let cmd = if rest.first().map(String::as_str) == Some("--") {
        &rest[1..]
    } else {
        rest.as_slice()
    };
    if cmd.is_empty() {
        return Err("usage: workpen run [--root DIR] [--extra-root DIR] [--] CMD...".into());
    }
    let joined = cmd.join(" ");
    let policy = DenyPolicy::default();
    if let Err(e) = reject_command_secret_path_tokens(&joined, &policy) {
        return Err(e.to_string());
    }
    let guard = PathGuard::with_extra_roots(&root, &extras).map_err(|e| e.to_string())?;
    if let Err(e) = workpen::check_dests(&guard, &[Path::new(&root)]) {
        return Err(e.to_string());
    }
    workpen::process_jail(&root, &extras)
        .and_then(|policy| policy.apply())
        .map_err(|e| e.to_string())?;
    let status = Command::new(&cmd[0])
        .args(&cmd[1..])
        .current_dir(&root)
        .status()
        .map_err(|e| e.to_string())?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

fn cmd_gc(args: &[String]) -> Result<ExitCode, String> {
    let (root, _extras, rest) = parse_roots(args)?;
    let mut max_age = None;
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == "--max-age" {
            let raw = rest
                .get(i + 1)
                .ok_or_else(|| "usage: workpen gc [--root DIR] --max-age DUR".to_string())?;
            max_age = Some(parse_duration(raw)?);
            i += 2;
            continue;
        }
        return Err(format!("unknown gc flag: {}", rest[i]));
    }
    let max_age =
        max_age.ok_or_else(|| "usage: workpen gc [--root DIR] --max-age DUR".to_string())?;
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let report = gc_leftovers(&root, &GcPolicy::new(max_age), SystemTime::now(), &cwd)
        .map_err(|e| e.to_string())?;
    for path in &report.removed {
        println!("removed {}", path.display());
    }
    for (path, reason) in &report.kept {
        println!("kept {} ({reason:?})", path.display());
    }
    Ok(ExitCode::SUCCESS)
}

fn parse_roots(args: &[String]) -> Result<(PathBuf, Vec<PathBuf>, Vec<String>), String> {
    let mut root = std::env::current_dir().map_err(|e| e.to_string())?;
    let mut extras = Vec::new();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => {
                root = PathBuf::from(
                    args.get(i + 1)
                        .ok_or_else(|| "missing --root value".to_string())?,
                );
                i += 2;
            }
            "--extra-root" => {
                extras.push(PathBuf::from(
                    args.get(i + 1)
                        .ok_or_else(|| "missing --extra-root value".to_string())?,
                ));
                i += 2;
            }
            "--" => {
                rest.extend(args[i + 1..].iter().cloned());
                break;
            }
            _ => {
                rest.extend(args[i..].iter().cloned());
                break;
            }
        }
    }
    Ok((root, extras, rest))
}

fn parse_duration(raw: &str) -> Result<Duration, String> {
    if let Some(n) = raw.strip_suffix('d') {
        return Ok(Duration::from_secs(parse_u64(n)? * 86400));
    }
    if let Some(n) = raw.strip_suffix('h') {
        return Ok(Duration::from_secs(parse_u64(n)? * 3600));
    }
    if let Some(n) = raw.strip_suffix('m') {
        return Ok(Duration::from_secs(parse_u64(n)? * 60));
    }
    if let Some(n) = raw.strip_suffix('s') {
        return Ok(Duration::from_secs(parse_u64(n)?));
    }
    Ok(Duration::from_secs(parse_u64(raw)?))
}

fn parse_u64(raw: &str) -> Result<u64, String> {
    raw.parse().map_err(|_| format!("invalid duration: {raw}"))
}
