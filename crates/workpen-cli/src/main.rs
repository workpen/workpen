//! workpen CLI. Wrap, explain, leftover GC.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime};

use workpen::{
    CheckDestError, DenyPolicy, ExtraRootError, GcConfig, GcDecision, KernelError, PathGuard,
    PathGuardError, check_command_argv, dest_under_root, parse_max_age, resolve_extra_root_pair,
    resolve_workspace_root, run_gc_with_policy,
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

const TOP_USAGE: &str = "\
usage: workpen [--version] [--help] <why|run|gc> ...
  why [--root DIR] [--extra-root DIR] PATH
  run [--root DIR] [--extra-root DIR] [--timeout DUR] [--tty] [--] CMD...
  gc  [--root DIR] --max-age DUR [--dry-run] [--leftover DIR]

By default the child cannot use the network. It may read system paths and write inside the workspace. --extra-root is read-write, so a write outside the workspace needs that flag. Secret files are dest-denied before the child starts. / and $HOME are not roots.
Exit status 0 is success. 1 is a why denial. 2 is usage or a setup failure. 3 is a policy refusal before the child starts. 124 is a timeout. 127 means the program was not found. The child status is passed through, including 2, 3, and 127.";

const WHY_USAGE: &str = "usage: workpen why [--root DIR] [--extra-root DIR] PATH";

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    if args.is_empty() {
        eprintln!("{TOP_USAGE}");
        return Ok(ExitCode::from(2));
    }
    if args[0] == "--version" || args[0] == "-V" {
        println!("{}", workpen::VERSION);
        return Ok(ExitCode::SUCCESS);
    }
    if is_top_help(&args[0]) {
        println!("{TOP_USAGE}");
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
    if wants_help(&rest) {
        println!("{WHY_USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(flag) = rest.iter().find(|t| t.starts_with('-')) {
        return Err(format!(
            "unknown flag: {flag} (use --root DIR or --extra-root DIR)"
        ));
    }
    if rest.len() > 1 {
        return Err(format!("unexpected argument: {} ({WHY_USAGE})", rest[1]));
    }
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = resolve_workspace_root(&cwd, &root.to_string_lossy()).map_err(|e| e.to_string())?;
    let (extras, _presented) = resolve_extras(&cwd, &extras).map_err(|e| e.to_string())?;
    let path = rest.first().ok_or_else(|| WHY_USAGE.to_string())?;
    let guard = PathGuard::with_extra_roots(&root, &extras).map_err(|e| e.to_string())?;
    let dest = why_dest(&root, path);
    let policy = DenyPolicy::from_workspace(&root).map_err(|e| e.to_string())?;
    match workpen::check_dest(&dest.to_string_lossy(), &policy, Some(&guard)) {
        Ok(resolved) => {
            println!("allowed {}", resolved.display());
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

const RUN_USAGE: &str =
    "usage: workpen run [--root DIR] [--extra-root DIR] [--timeout DUR] [--tty] [--] CMD...";

const RUN_HELP: &str = "\
usage: workpen run [--root DIR] [--extra-root DIR] [--timeout DUR] [--tty] [--] CMD...
The network is blocked. --extra-root is read-write. Dest-deny runs before the child starts, and on Linux the child is not started when secret names cannot be hidden. Exit 124 means the timeout fired.";

fn cmd_run(args: &[String]) -> Result<ExitCode, String> {
    let (root, extras, rest) = parse_roots(args)?;
    if wants_help(&rest) {
        println!("{RUN_HELP}");
        return Ok(ExitCode::SUCCESS);
    }
    let (timeout, tty, rest) = peel_run_flags(&rest)?;
    let saw_dashdash = rest.first().map(String::as_str) == Some("--");
    let cmd_preview: &[String] = if saw_dashdash { &rest[1..] } else { rest };
    if !saw_dashdash && version_flag_before_child(cmd_preview) {
        println!("{}", workpen::VERSION);
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(flag) = rest.first().filter(|t| t.starts_with('-') && *t != "--") {
        return Err(format!("unknown flag: {flag} ({RUN_USAGE})"));
    }
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = match resolve_workspace_root(&cwd, &root.to_string_lossy()) {
        Ok(root) => root,
        Err(err @ PathGuardError::Home(_)) => return refuse(err),
        Err(err) => return Err(err.to_string()),
    };
    let (extras, presented) = match resolve_extras(&cwd, &extras) {
        Ok(pair) => pair,
        Err(err @ ExtraRootError::Home(_)) => return refuse(err),
        Err(err) => return Err(err.to_string()),
    };
    let cmd = if rest.first().map(String::as_str) == Some("--") {
        &rest[1..]
    } else {
        rest
    };
    if cmd.is_empty() {
        return Err(RUN_USAGE.into());
    }
    let policy = DenyPolicy::from_workspace(&root).map_err(|e| e.to_string())?;
    let guard = match PathGuard::with_extra_roots(&root, &extras) {
        Ok(guard) => guard,
        Err(err @ PathGuardError::Home(_)) => return refuse(err),
        Err(err) => return Err(err.to_string()),
    };
    if let Err(err) = check_command_argv(cmd, guard.canon_root(), &policy) {
        return refuse(err);
    }
    let jail = match workpen::process_jail(guard.canon_root(), &presented) {
        Ok(policy) => policy.with_require_dest_hide(),
        Err(err @ KernelError::Home(_))
        | Err(err @ KernelError::FsRoot(_))
        | Err(err @ KernelError::DestDeny(_)) => return refuse(err),
        Err(err) => return Err(err.to_string()),
    };
    let resolved = match resolve_child_program(&cmd[0], guard.canon_root()) {
        Ok(path) => path,
        Err(()) => {
            eprintln!("command not found: {}", cmd[0]);
            return Ok(ExitCode::from(127));
        }
    };
    let (program, args) = workpen::with_bash_noprofile(&resolved, &cmd[1..]);
    let mut child = Command::new(program);
    child.args(args).current_dir(guard.canon_root());
    // Copy child pipes to this process as bytes arrive. A Vec of the whole
    // stream would grow without bound (`yes` under --timeout). Inherited
    // child stdout to a file outside --root is a Seatbelt/DACL dest write.
    let result = match (timeout, tty) {
        (Some(limit), true) => jail.run_child_timeout_forward_pty(child, limit),
        (None, true) => jail
            .run_child_forward_pty(child)
            .map(|(applied, status)| (applied, status, false)),
        (Some(limit), false) => jail.run_child_timeout_forward(child, limit),
        (None, false) => jail
            .run_child_forward(child)
            .map(|(applied, status)| (applied, status, false)),
    };
    let (_applied, status, timed_out) = match result {
        Err(KernelError::Timeout) => {
            eprintln!("child killed after the deadline");
            return Ok(ExitCode::from(124));
        }
        Err(KernelError::Restore(e)) => {
            return Err(format!(
                "child finished but {e}; workspace ACL may still grant the write-restricted SID"
            ));
        }
        Err(err @ KernelError::DestDeny(_))
        | Err(err @ KernelError::Home(_))
        | Err(err @ KernelError::FsRoot(_)) => return refuse(err),
        Err(e) => {
            let mut msg = format!("failed to spawn {}: {e}", resolved.display());
            if program_outside_roots(&resolved, guard.canon_root(), &presented) {
                msg.push_str("; pass --extra-root for that directory if the program should run");
            }
            return Err(msg);
        }
        Ok(ok) => ok,
    };
    if timed_out {
        eprintln!("child killed after the deadline");
        return Ok(ExitCode::from(124));
    }
    if status.code().is_none() && program_outside_roots(&resolved, guard.canon_root(), &presented) {
        return Err(format!(
            "failed to spawn {}: kernel wrap apply failed: program is outside the readable roots; pass --extra-root for that directory if the program should run",
            resolved.display()
        ));
    }
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

fn peel_run_flags(rest: &[String]) -> Result<(Option<Duration>, bool, &[String]), String> {
    let mut timeout = None;
    let mut tty = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--timeout" => {
                let raw = flag_value(rest, i, "--timeout")?;
                timeout = Some(parse_max_age(raw).map_err(|e| e.to_string())?);
                i += 2;
            }
            "--tty" => {
                tty = true;
                i += 1;
            }
            _ => break,
        }
    }
    Ok((timeout, tty, &rest[i..]))
}

fn cmd_gc(args: &[String]) -> Result<ExitCode, String> {
    let (root, extras, rest) = parse_roots(args)?;
    if wants_help(&rest) {
        println!("{}", gc_usage());
        println!(
            "gc looks under .workpen-worktrees, or the directory named by --leftover. It is not a target/ cleaner. When nothing is left, it prints that directory and the max-age token."
        );
        return Ok(ExitCode::SUCCESS);
    }
    if !extras.is_empty() {
        return Err("gc does not take --extra-root".into());
    }
    let mut max_age = None;
    let mut max_age_token = None;
    let mut leftover = None;
    let mut dry_run = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--max-age" => {
                let raw = flag_value(&rest, i, "--max-age")?;
                max_age = Some(parse_max_age(raw).map_err(|e| e.to_string())?);
                max_age_token = Some(raw.to_string());
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
    let max_age_token = max_age_token.ok_or_else(gc_usage)?;
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = resolve_workspace_root(&cwd, &root.to_string_lossy()).map_err(|e| e.to_string())?;
    let policy = DenyPolicy::from_workspace(&root).map_err(|e| e.to_string())?;
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
    let rows = run_gc_with_policy(&root, &cfg, &policy).map_err(|e| e.to_string())?;
    if rows.is_empty() {
        println!(
            "no leftover worktrees under {} (max-age {max_age_token})",
            cfg.leftover_dir.display()
        );
    } else {
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
        println!("{} worktrees", rows.len());
    }
    Ok(ExitCode::SUCCESS)
}

/// Policy refusal. `Ok(3)` so `main` does not turn the status into 2.
fn refuse(err: impl std::fmt::Display) -> Result<ExitCode, String> {
    eprintln!("{err}");
    Ok(ExitCode::from(3))
}

/// `--version` / `-V` in the program slot is Workpen's version.
/// A token after the program, or after `--`, belongs to the child.
fn version_flag_before_child(cmd: &[String]) -> bool {
    matches!(
        cmd.first().map(String::as_str),
        Some("--version") | Some("-V")
    )
}

/// Find the program in the parent. A slash path is relative to the child cwd.
/// A bare name uses the parent's `PATH`, keeping the first match's spelling.
fn program_outside_roots(program: &Path, root: &Path, extras: &[PathBuf]) -> bool {
    let canon = std::fs::canonicalize(program).unwrap_or_else(|_| program.to_path_buf());
    let mut bases = Vec::with_capacity(1 + extras.len());
    bases.push(std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf()));
    for extra in extras {
        bases.push(std::fs::canonicalize(extra).unwrap_or_else(|_| extra.clone()));
    }
    !bases.iter().any(|base| canon.starts_with(base))
}

fn resolve_child_program(argv0: &str, child_cwd: &Path) -> Result<PathBuf, ()> {
    let raw = Path::new(argv0);
    let has_sep = argv0.contains('/') || argv0.contains('\\');
    if raw.is_absolute() || has_sep {
        let candidate = if raw.is_absolute() {
            raw.to_path_buf()
        } else {
            child_cwd.join(raw)
        };
        return if candidate.is_file() {
            Ok(candidate)
        } else {
            Err(())
        };
    }
    let path_var = std::env::var_os("PATH").unwrap_or_else(|| OsStr::new("").to_os_string());
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(argv0);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(())
}

/// Blank `why` PATH stays blank so PathGuard reports empty, not the workspace.
fn why_dest(root: &Path, path: &str) -> PathBuf {
    if path.trim().is_empty() {
        PathBuf::from(path)
    } else {
        dest_under_root(root, path)
    }
}

fn resolve_extras(
    cwd: &Path,
    extras: &[PathBuf],
) -> Result<(Vec<PathBuf>, Vec<PathBuf>), ExtraRootError> {
    let mut canon = Vec::with_capacity(extras.len());
    let mut presented = Vec::with_capacity(extras.len());
    for extra in extras {
        let (presented_abs, resolved) = resolve_extra_root_pair(cwd, &extra.to_string_lossy())?;
        presented.push(presented_abs);
        canon.push(resolved);
    }
    Ok((canon, presented))
}

fn gc_usage() -> String {
    "usage: workpen gc [--root DIR] --max-age DUR [--dry-run] [--leftover DIR]".to_string()
}

fn is_top_help(arg: &str) -> bool {
    matches!(arg, "help" | "--help" | "-h")
}

fn is_help_flag(arg: &str) -> bool {
    matches!(arg, "--help" | "-h")
}

/// `--help` / `-h` before `--` is CLI help. After `--` it is the child.
fn wants_help(tokens: &[String]) -> bool {
    tokens
        .iter()
        .take_while(|t| t.as_str() != "--")
        .any(|t| is_help_flag(t))
}

/// Next token after a flag, or error if missing or another `--` flag.
fn flag_value<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str, String> {
    match args.get(i + 1) {
        Some(v) if !v.starts_with("--") => Ok(v.as_str()),
        _ => Err(if flag == "--root" || flag == "--extra-root" {
            format!("missing {flag} value")
        } else if flag == "--timeout" {
            RUN_USAGE.into()
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
