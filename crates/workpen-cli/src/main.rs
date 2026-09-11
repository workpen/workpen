//! workpen CLI. Wrap, explain, leftover GC.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::SystemTime;

use workpen::{
    CheckDestError, DenyPolicy, GcConfig, GcDecision, PathGuard, parse_max_age,
    reject_command_secret_path_tokens, resolve_extra_root, run_gc,
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
        other => Err(format!("unknown command: {other} (use why, run, or gc)")),
    }
}

fn cmd_why(args: &[String]) -> Result<ExitCode, String> {
    let (root, extras, rest) = parse_roots(args)?;
    let extras = resolve_extras(&root, &extras)?;
    let path = rest
        .first()
        .ok_or_else(|| "usage: workpen why [--root DIR] [--extra-root DIR] PATH".to_string())?;
    let guard = PathGuard::with_extra_roots(&root, &extras).map_err(|e| e.to_string())?;
    let dest = why_dest(&root, path);
    match workpen::check_dest(
        &dest.to_string_lossy(),
        &DenyPolicy::default(),
        Some(&guard),
    ) {
        Ok(_) => {
            println!("allowed");
            Ok(ExitCode::SUCCESS)
        }
        Err(CheckDestError::DestDeny(e)) => {
            println!("{e}");
            Ok(ExitCode::from(1))
        }
        Err(CheckDestError::PathGuard(e)) => {
            println!("{e}");
            Ok(ExitCode::from(1))
        }
        Err(e) => Err(e.to_string()),
    }
}

fn cmd_run(args: &[String]) -> Result<ExitCode, String> {
    let (root, extras, rest) = parse_roots(args)?;
    let extras = resolve_extras(&root, &extras)?;
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
    for token in cmd {
        if token.starts_with('-') {
            continue;
        }
        let dest = dest_under_root(&root, token);
        if let Err(e) = workpen::check_dest(&dest.to_string_lossy(), &policy, None) {
            return Err(e.to_string());
        }
    }
    let mut child = Command::new(&cmd[0]);
    child.args(&cmd[1..]).current_dir(&root);
    workpen::process_jail(&root, &extras)
        .and_then(|policy| policy.apply_pre_exec(&mut child))
        .map_err(|e| e.to_string())?;
    let status = child
        .status()
        .map_err(|e| format!("failed to spawn {}: {e}", cmd[0]))?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

fn cmd_gc(args: &[String]) -> Result<ExitCode, String> {
    let (root, _extras, rest) = parse_roots(args)?;
    let mut max_age = None;
    let mut leftover = None;
    let mut dry_run = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--max-age" => {
                let raw = rest.get(i + 1).ok_or_else(|| {
                    "usage: workpen gc [--root DIR] --max-age DUR [--dry-run] [--leftover DIR]"
                        .to_string()
                })?;
                max_age = Some(parse_max_age(raw).map_err(|e| e.to_string())?);
                i += 2;
            }
            "--leftover" => {
                leftover = Some(PathBuf::from(rest.get(i + 1).ok_or_else(|| {
                    "usage: workpen gc [--root DIR] --max-age DUR [--dry-run] [--leftover DIR]"
                        .to_string()
                })?));
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            other => {
                return Err(format!(
                    "unknown gc flag: {other} (use --max-age, --dry-run, --leftover, or --help)"
                ));
            }
        }
    }
    let max_age = max_age.ok_or_else(|| {
        "usage: workpen gc [--root DIR] --max-age DUR [--dry-run] [--leftover DIR]".to_string()
    })?;
    let mut cfg = GcConfig::new(&root, max_age);
    cfg.now = SystemTime::now();
    cfg.dry_run = dry_run;
    if let Some(dir) = leftover {
        cfg.leftover_dir = if dir.is_absolute() {
            dir
        } else {
            root.join(dir)
        };
    }
    let rows = run_gc(&root, &cfg).map_err(|e| e.to_string())?;
    for (path, decision) in &rows {
        match decision {
            GcDecision::Keep { reason } => {
                println!("keep {} ({})", path.display(), reason.as_str());
            }
            GcDecision::Reclaim { .. } if dry_run => {
                println!("dry-run: would reclaim {}", path.display());
            }
            GcDecision::Reclaim { .. } => {
                println!("reclaimed {}", path.display());
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Join a relative dest to `--root`. Absolute dests stay as given.
fn dest_under_root(root: &Path, path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}

/// Blank `why` PATH stays blank so PathGuard reports empty, not the workspace.
fn why_dest(root: &Path, path: &str) -> PathBuf {
    if path.trim().is_empty() {
        PathBuf::from(path)
    } else {
        dest_under_root(root, path)
    }
}

fn resolve_extras(root: &Path, extras: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    extras
        .iter()
        .map(|extra| resolve_extra_root(root, &extra.to_string_lossy()).map_err(|e| e.to_string()))
        .collect()
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
