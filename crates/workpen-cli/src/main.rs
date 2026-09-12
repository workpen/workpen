//! workpen CLI. Wrap, explain, leftover GC.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::SystemTime;

use workpen::{
    CheckDestError, DenyPolicy, GcConfig, GcDecision, PathGuard, check_command_argv,
    dest_under_root, parse_max_age, resolve_extra_root, resolve_workspace_root, run_gc,
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
    if let Some(flag) = rest.iter().find(|t| t.starts_with('-')) {
        return Err(format!(
            "unknown flag: {flag} (use --root DIR or --extra-root DIR)"
        ));
    }
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = resolve_workspace_root(&cwd, &root.to_string_lossy()).map_err(|e| e.to_string())?;
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
    if let Some(flag) = rest.first().filter(|t| t.starts_with('-') && *t != "--") {
        return Err(format!(
            "unknown flag: {flag} (use --root DIR or --extra-root DIR)"
        ));
    }
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = resolve_workspace_root(&cwd, &root.to_string_lossy()).map_err(|e| e.to_string())?;
    let extras = resolve_extras(&root, &extras)?;
    let cmd = if rest.first().map(String::as_str) == Some("--") {
        &rest[1..]
    } else {
        rest.as_slice()
    };
    if cmd.is_empty() {
        return Err("usage: workpen run [--root DIR] [--extra-root DIR] [--] CMD...".into());
    }
    let policy = DenyPolicy::default();
    let guard = PathGuard::with_extra_roots(&root, &extras).map_err(|e| e.to_string())?;
    if let Err(e) = check_command_argv(cmd, guard.canon_root(), &policy) {
        return Err(e.to_string());
    }
    let mut child = Command::new(&cmd[0]);
    child.args(&cmd[1..]).current_dir(guard.canon_root());
    workpen::process_jail(guard.canon_root(), &extras)
        .and_then(|policy| policy.apply_pre_exec(&mut child))
        .map_err(|e| e.to_string())?;
    let status = child
        .status()
        .map_err(|e| format!("failed to spawn {}: {e}", cmd[0]))?;
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

fn cmd_gc(args: &[String]) -> Result<ExitCode, String> {
    let (root, extras, rest) = parse_roots(args)?;
    if !extras.is_empty() {
        return Err("gc does not take --extra-root".into());
    }
    let mut max_age = None;
    let mut leftover = None;
    let mut dry_run = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--max-age" => {
                let raw = flag_value(&rest, i, "--max-age")?;
                max_age = Some(parse_max_age(raw).map_err(|e| e.to_string())?);
                i += 2;
            }
            "--leftover" => {
                leftover = Some(PathBuf::from(flag_value(&rest, i, "--leftover")?));
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            other => {
                return Err(format!(
                    "unknown gc flag: {other} (use --max-age, --dry-run, or --leftover)"
                ));
            }
        }
    }
    let max_age = max_age.ok_or_else(gc_usage)?;
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

fn gc_usage() -> String {
    "usage: workpen gc [--root DIR] --max-age DUR [--dry-run] [--leftover DIR]".to_string()
}

/// Next token after a flag, or error if missing or another `--` flag.
fn flag_value<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str, String> {
    match args.get(i + 1) {
        Some(v) if !v.starts_with("--") => Ok(v.as_str()),
        _ => Err(if flag == "--root" || flag == "--extra-root" {
            format!("missing {flag} value")
        } else {
            gc_usage()
        }),
    }
}

fn parse_roots(args: &[String]) -> Result<(PathBuf, Vec<PathBuf>, Vec<String>), String> {
    let mut root = std::env::current_dir().map_err(|e| e.to_string())?;
    let mut extras = Vec::new();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => {
                root = PathBuf::from(flag_value(args, i, "--root")?);
                i += 2;
            }
            "--extra-root" => {
                extras.push(PathBuf::from(flag_value(args, i, "--extra-root")?));
                i += 2;
            }
            "--" => {
                rest.extend(args[i..].iter().cloned());
                break;
            }
            _ => {
                rest.push(args[i].clone());
                i += 1;
            }
        }
    }
    Ok((root, extras, rest))
}
