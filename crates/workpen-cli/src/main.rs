//! workpen CLI. Wrap, explain, leftover GC.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime};

use workpen::{
    CheckDestError, DenyPolicy, DestDenyError, ExtraRootError, GcConfig, GcDecision, KernelError,
    PathGuard, PathGuardError, check_command_argv, dest_under_root, parse_max_age,
    resolve_extra_root_pair, resolve_workspace_root, run_gc_with_policy,
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
usage: workpen [--version] [--help] <why|run|policy|gc|init|doctor> ...
  why [--root DIR] [--extra-root DIR] PATH
  run [--root DIR] [--extra-root DIR] [--read DIR] [--write DIR] [--net] [--policy] [--timeout DUR] [--tty] [--env NAME[=VALUE]] [--env-clear] [--] CMD...
  policy [--root DIR] [--extra-root DIR] [--read DIR] [--write DIR] [--net] [--] [CMD...]
  gc  [--root DIR] --max-age DUR [--dry-run] [--leftover DIR]
  init [--root DIR]
  doctor

By default the child cannot use the network. It may read system paths and write inside the workspace. --extra-root is read-write, so a write outside the workspace needs that flag. Secret files are dest-denied before the child starts. / and $HOME are not roots.
why reports whether one path is dest-denied under the root. It does not spawn.
run dest-denies argv, then starts one jailed child when the jail applies.
gc reclaims leftover worktrees under .workpen-worktrees. It does not clean target/.
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
        "run" => cmd_run(&args[1..], false),
        "policy" => cmd_run(&args[1..], true),
        "gc" => cmd_gc(&args[1..]),
        "init" => cmd_init(&args[1..]),
        "doctor" => cmd_doctor(&args[1..]),
        other => Err(format!(
            "unknown command: {other} (use why, run, policy, gc, init, or doctor)"
        )),
    }
}

const INIT_USAGE: &str = "usage: workpen init [--root DIR]";

const DOCTOR_USAGE: &str = "\
usage: workpen doctor
Print whether this machine can jail a child. Does not start a command.
Exit 0 when a child can be jailed, including when Windows WFP is skipped.
Exit 1 when the kernel jail is unavailable, or on Linux when secret names cannot be hidden.";

const REMOUNT_UNAVAILABLE: &str =
    "remount: unavailable (unshare, user-namespace id map, or private remount of /)";

fn cmd_doctor(args: &[String]) -> Result<ExitCode, String> {
    if wants_help(args) {
        println!("{DOCTOR_USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    if !args.is_empty() {
        return Err(format!("doctor does not take arguments ({DOCTOR_USAGE})"));
    }
    let facts = workpen::collect_doctor_facts();
    println!("os: {}", std::env::consts::OS);
    println!("version: {}", workpen::VERSION);
    if facts.kernel_supported {
        println!("kernel: supported");
    } else {
        println!("kernel: unsupported");
    }
    match facts.remount_available {
        Some(true) => println!("remount: available"),
        Some(false) => println!("{REMOUNT_UNAVAILABLE}"),
        None => {}
    }
    if facts.setup_failed {
        println!("appcontainer: unavailable");
    } else if let Some(skipped) = facts.wfp_skipped {
        println!("appcontainer: available");
        if skipped {
            println!("wfp: skipped");
        } else {
            println!("wfp: applied");
        }
        println!("network: blocked");
    }
    if workpen::doctor_fails(facts) {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

const AGENT_LOCK_TEMPLATE: &str = "\
# extra dest-deny globs, one per line
# A line that starts with # is a comment. Blank lines are skipped.
# secrets/**
";

fn cmd_init(args: &[String]) -> Result<ExitCode, String> {
    let (root, extras, rest) = parse_roots(args, &[], &[])?;
    if wants_help(&rest) {
        println!("{INIT_USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    if !extras.is_empty() {
        return Err(format!("init does not take --extra-root ({INIT_USAGE})"));
    }
    if let Some(flag) = rest.first() {
        return Err(format!("unknown argument: {flag} ({INIT_USAGE})"));
    }
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = match resolve_workspace_root(&cwd, &root.to_string_lossy()) {
        Ok(root) => root,
        Err(err @ PathGuardError::Home(_)) => return refuse(err),
        Err(err) => return Err(err.to_string()),
    };
    if path_is_filesystem_root(&root) {
        return refuse(format!(
            "refused filesystem root {}; use a subdirectory, not `/`",
            root.display()
        ));
    }
    let path = root.join(workpen::AGENT_LOCK_NAME);
    if path.exists() {
        return Err(format!(
            "agent.lock already exists at {}; init does not change it",
            path.display()
        ));
    }
    std::fs::write(&path, AGENT_LOCK_TEMPLATE).map_err(|e| e.to_string())?;
    println!("wrote {}", path.display());
    Ok(ExitCode::SUCCESS)
}

fn cmd_why(args: &[String]) -> Result<ExitCode, String> {
    let (root, extras, rest) = parse_roots(args, &[], &["--json"])?;
    let json = rest.iter().any(|token| token == "--json");
    let rest: Vec<String> = rest
        .iter()
        .filter(|token| token.as_str() != "--json")
        .cloned()
        .collect();
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
    let root = match resolve_workspace_root(&cwd, &root.to_string_lossy()) {
        Ok(root) => root,
        Err(PathGuardError::Home(path)) if json => return json_guard(1, &path),
        Err(err) => return Err(err.to_string()),
    };
    let (extras, _presented) = match resolve_extras(&cwd, &extras) {
        Ok(pair) => pair,
        Err(ExtraRootError::Home(path)) if json => return json_guard(1, &path),
        Err(err) => return Err(err.to_string()),
    };
    let path = rest.first().ok_or_else(|| WHY_USAGE.to_string())?;
    let guard = PathGuard::with_extra_roots(&root, &extras).map_err(|e| e.to_string())?;
    let dest = why_dest(&root, path);
    let policy = DenyPolicy::from_workspace(&root).map_err(|e| e.to_string())?;
    match workpen::check_dest(&dest.to_string_lossy(), &policy, Some(&guard)) {
        Ok(resolved) => {
            if json {
                let shown = resolved.display().to_string();
                println!("{}", json_line("allowed", 0, Some(&shown), None, None));
            } else {
                println!("allowed {}", resolved.display());
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(err @ CheckDestError::DestDeny(_)) | Err(err @ CheckDestError::PathGuard(_)) => {
            check_dest_status(json, 1, &err)
        }
        Err(err @ CheckDestError::SpecialFile { .. }) => check_dest_status(json, 1, &err),
        Err(e) => Err(e.to_string()),
    }
}

const RUN_USAGE: &str = "\
usage: workpen run [--root DIR] [--extra-root DIR] [--read DIR] [--write DIR] [--net] [--policy] [--json] \
[--timeout DUR] [--tty] [--env NAME[=VALUE]] [--env-clear] [--] CMD...";

const RUN_HELP: &str = "\
usage: workpen run [--root DIR] [--extra-root DIR] [--read DIR] [--write DIR] [--net] [--policy] [--json] \
[--timeout DUR] [--tty] [--env NAME[=VALUE]] [--env-clear] [--] CMD...
The network is blocked unless --net is set. --extra-root and --write are read-write. --read is read-only. Dest-deny runs before the child starts, and on Linux the child is not started when secret names cannot be hidden. --policy prints the jail and does not start the child. Exit 124 means the timeout fired. --env opts a name back in. --env-clear drops inherited names except PATH, then applies every --env. Loaders such as LD_PRELOAD stay removed.";

fn cmd_run(args: &[String], force_report: bool) -> Result<ExitCode, String> {
    let (root, extras, rest) = parse_roots(
        args,
        &["--timeout", "--env", "--read", "--write"],
        &["--tty", "--env-clear", "--policy", "--net", "--json"],
    )?;
    if wants_help(&rest) {
        println!("{RUN_HELP}");
        return Ok(ExitCode::SUCCESS);
    }
    let flags = peel_run_flags(&rest)?;
    let timeout = flags.timeout;
    let tty = flags.tty;
    let env_clear = flags.env_clear;
    let env_sets = flags.env;
    let report = force_report || flags.report;
    let allow_net = flags.allow_net;
    let json = flags.json;
    let read_roots = flags.read;
    let write_roots = flags.write;
    let rest = flags.rest;
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
        Err(PathGuardError::Home(path)) => return refuse_home(json, path),
        Err(err) => return Err(err.to_string()),
    };
    let (mut extras, mut presented) = match resolve_extras(&cwd, &extras) {
        Ok(pair) => pair,
        Err(ExtraRootError::Home(path)) => return refuse_extra_home(json, path),
        Err(err) => return Err(err.to_string()),
    };
    for write in &write_roots {
        match resolve_extra_root_pair(&cwd, &write.to_string_lossy()) {
            Ok((shown, canon)) => {
                presented.push(shown);
                extras.push(canon);
            }
            Err(ExtraRootError::Home(path)) => return refuse_extra_home(json, path),
            Err(err) => return Err(err.to_string()),
        }
    }
    let mut read_canon = Vec::new();
    for read in &read_roots {
        match resolve_extra_root_pair(&cwd, &read.to_string_lossy()) {
            Ok((_shown, canon)) => read_canon.push(canon),
            Err(ExtraRootError::Home(path)) => return refuse_extra_home(json, path),
            Err(err) => return Err(err.to_string()),
        }
    }
    let cmd = if rest.first().map(String::as_str) == Some("--") {
        &rest[1..]
    } else {
        rest
    };
    if cmd.is_empty() && !report {
        return Err(RUN_USAGE.into());
    }
    let policy = DenyPolicy::from_workspace(&root).map_err(|e| e.to_string())?;
    let guard = match PathGuard::with_extra_roots(&root, &extras) {
        Ok(guard) => guard,
        Err(PathGuardError::Home(path)) => return refuse_home(json, path),
        Err(err) => return Err(err.to_string()),
    };
    let mut jail = match workpen::process_jail(guard.canon_root(), &presented) {
        Ok(policy) => policy.with_require_dest_hide().with_network(!allow_net),
        Err(err @ KernelError::Home(_))
        | Err(err @ KernelError::FsRoot(_))
        | Err(err @ KernelError::DestDeny(_)) => return refuse_kernel(json, err),
        Err(err) => return Err(err.to_string()),
    };
    for read in &read_canon {
        jail = match jail.with_read_root(read) {
            Ok(jail) => jail,
            Err(err @ KernelError::Home(_))
            | Err(err @ KernelError::FsRoot(_))
            | Err(err @ KernelError::DestDeny(_)) => return refuse_kernel(json, err),
            Err(err) => return Err(err.to_string()),
        };
    }
    if report {
        print_policy(&jail, &policy);
        if !cmd.is_empty()
            && let Err(err) = check_command_argv(cmd, guard.canon_root(), &policy)
        {
            println!("would-deny: {err}");
        }
        return Ok(ExitCode::SUCCESS);
    }
    if let Err(err) = check_command_argv(cmd, guard.canon_root(), &policy) {
        return check_dest_status(json, 3, &err);
    }
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
    apply_child_env(&mut child, env_clear, &env_sets);
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
        | Err(err @ KernelError::FsRoot(_)) => return refuse_kernel(json, err),
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

struct RunFlags<'a> {
    timeout: Option<Duration>,
    tty: bool,
    env_clear: bool,
    env: Vec<(String, String)>,
    report: bool,
    allow_net: bool,
    json: bool,
    read: Vec<PathBuf>,
    write: Vec<PathBuf>,
    rest: &'a [String],
}

fn peel_run_flags(rest: &[String]) -> Result<RunFlags<'_>, String> {
    let mut timeout = None;
    let mut tty = false;
    let mut env_clear = false;
    let mut env_sets = Vec::new();
    let mut report = false;
    let mut allow_net = false;
    let mut json = false;
    let mut read = Vec::new();
    let mut write = Vec::new();
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
            "--env-clear" => {
                env_clear = true;
                i += 1;
            }
            "--env" => {
                let raw = flag_value(rest, i, "--env")?;
                env_sets.push(parse_env_set(raw)?);
                i += 2;
            }
            "--policy" => {
                report = true;
                i += 1;
            }
            "--net" => {
                allow_net = true;
                i += 1;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "--read" => {
                read.push(PathBuf::from(flag_value(rest, i, "--read")?));
                i += 2;
            }
            "--write" => {
                write.push(PathBuf::from(flag_value(rest, i, "--write")?));
                i += 2;
            }
            _ => break,
        }
    }
    Ok(RunFlags {
        timeout,
        tty,
        env_clear,
        env: env_sets,
        report,
        allow_net,
        json,
        read,
        write,
        rest: &rest[i..],
    })
}

fn print_policy(jail: &workpen::KernelPolicy, policy: &DenyPolicy) {
    for grant in jail.grants() {
        let access = match grant.access {
            workpen::KernelAccess::ReadWrite => "read-write",
            workpen::KernelAccess::Read => "read",
        };
        println!("{access}: {}", grant.path.display());
    }
    let network = if jail.network_blocked() {
        "blocked"
    } else {
        "allowed"
    };
    println!("network: {network}");
    for glob in policy.globs() {
        println!("deny: {glob}");
    }
}

fn parse_env_set(raw: &str) -> Result<(String, String), String> {
    if let Some((name, value)) = raw.split_once('=') {
        if name.is_empty() {
            return Err(format!("--env needs a name ({RUN_USAGE})"));
        }
        return Ok((name.to_string(), value.to_string()));
    }
    if raw.is_empty() {
        return Err(format!("--env needs a name ({RUN_USAGE})"));
    }
    let value = std::env::var(raw).unwrap_or_default();
    Ok((raw.to_string(), value))
}

fn apply_child_env(child: &mut Command, env_clear: bool, env_sets: &[(String, String)]) {
    if env_clear {
        child.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            child.env("PATH", path);
        }
        #[cfg(windows)]
        if let Some(root) = std::env::var_os("SystemRoot") {
            child.env("SystemRoot", &root);
        }
    }
    for (name, value) in env_sets {
        child.env(name, value);
    }
}

fn cmd_gc(args: &[String]) -> Result<ExitCode, String> {
    let (root, extras, rest) = parse_roots(args, &["--max-age", "--leftover"], &["--dry-run"])?;
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
        println!("{} leftover worktrees", rows.len());
    }
    Ok(ExitCode::SUCCESS)
}

/// Policy refusal. `Ok(3)` so `main` does not turn the status into 2.
fn refuse(err: impl std::fmt::Display) -> Result<ExitCode, String> {
    eprintln!("{err}");
    Ok(ExitCode::from(3))
}

fn path_is_filesystem_root(path: &Path) -> bool {
    match path.parent() {
        None => true,
        Some(parent) => parent.as_os_str().is_empty(),
    }
}

fn json_guard(code: u8, path: &Path) -> Result<ExitCode, String> {
    let shown = path.display().to_string();
    println!(
        "{}",
        json_line("denied", code, Some(&shown), None, Some("path_guard"))
    );
    Ok(ExitCode::from(code))
}

fn refuse_home(json: bool, path: PathBuf) -> Result<ExitCode, String> {
    if json {
        return json_guard(3, &path);
    }
    refuse(PathGuardError::Home(path))
}

fn refuse_extra_home(json: bool, path: PathBuf) -> Result<ExitCode, String> {
    if json {
        return json_guard(3, &path);
    }
    refuse(ExtraRootError::Home(path))
}

fn refuse_kernel(json: bool, err: KernelError) -> Result<ExitCode, String> {
    if !json {
        return refuse(err);
    }
    match err {
        KernelError::Home(path) | KernelError::FsRoot(path) => json_guard(3, &path),
        KernelError::DestDeny(inner) => check_dest_status(true, 3, &inner),
        other => refuse(other),
    }
}

fn check_dest_status(json: bool, code: u8, err: &CheckDestError) -> Result<ExitCode, String> {
    if json {
        println!("{}", check_dest_json(code, err));
        return Ok(ExitCode::from(code));
    }
    if code == 1 {
        println!("{err}");
        Ok(ExitCode::from(1))
    } else {
        eprintln!("{err}");
        Ok(ExitCode::from(code))
    }
}

fn check_dest_json(code: u8, err: &CheckDestError) -> String {
    match err {
        CheckDestError::DestDeny(DestDenyError::Denied(deny)) => {
            let kind = match deny.kind {
                workpen::DestDenyKind::DenyGlob => "deny_glob",
                workpen::DestDenyKind::HardlinkSibling => "hardlink_sibling",
            };
            json_line(
                "denied",
                code,
                Some(&deny.display),
                deny.matched.as_deref(),
                Some(kind),
            )
        }
        CheckDestError::PathGuard(PathGuardError::Home(path)) => {
            let shown = path.display().to_string();
            json_line("denied", code, Some(&shown), None, Some("path_guard"))
        }
        CheckDestError::SpecialFile { path, kind } => {
            json_line("denied", code, Some(path), Some(kind), Some("special_file"))
        }
        CheckDestError::DestDeny(_) | CheckDestError::PathGuard(_) => {
            json_line("denied", code, None, None, Some("path_guard"))
        }
        CheckDestError::Nul | CheckDestError::Directory { .. } | CheckDestError::Io(_) => {
            json_line("denied", code, None, None, None)
        }
    }
}

fn json_line(
    result: &str,
    code: u8,
    path: Option<&str>,
    matched: Option<&str>,
    kind: Option<&str>,
) -> String {
    format!(
        "{{\"result\":{},\"exit\":{code},\"path\":{},\"matched\":{},\"kind\":{}}}",
        json_string(result),
        json_opt(path),
        json_opt(matched),
        json_opt(kind),
    )
}

fn json_opt(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_string())
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
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
    // System programs such as /bin/cat are readable grants, not extra roots.
    for dir in [
        "/usr",
        "/bin",
        "/lib",
        "/lib64",
        "/sbin",
        "/System",
        "/Library",
        "/opt/homebrew",
        "/usr/local",
    ] {
        bases.push(PathBuf::from(dir));
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
        return first_existing_name(&candidate);
    }
    let path_var = std::env::var_os("PATH").unwrap_or_else(|| OsStr::new("").to_os_string());
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        if let Ok(found) = first_existing_name(&dir.join(argv0)) {
            return Ok(found);
        }
    }
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        let root = PathBuf::from(root);
        for dir in [root.join("System32"), root] {
            if let Ok(found) = first_existing_name(&dir.join(argv0)) {
                return Ok(found);
            }
        }
    }
    Err(())
}

/// `cmd` on Windows is `cmd.exe`. Keep the first spelling that exists.
fn first_existing_name(candidate: &Path) -> Result<PathBuf, ()> {
    if candidate.is_file() {
        return Ok(candidate.to_path_buf());
    }
    #[cfg(windows)]
    if candidate.extension().is_none() {
        let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        let stem = candidate
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        for ext in pathext.split(';') {
            let ext = ext.trim();
            if ext.is_empty() {
                continue;
            }
            let ext = if ext.starts_with('.') {
                ext.to_string()
            } else {
                format!(".{ext}")
            };
            let with_ext = candidate.with_file_name(format!("{stem}{ext}"));
            if with_ext.is_file() {
                return Ok(with_ext);
            }
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
        _ => Err(format!("missing {flag} value")),
    }
}

/// `--root` and `--extra-root` apply only before the command.
/// `valued` and `switches` are that subcommand's other flags, so
/// `run --timeout 5s --root DIR cmd` still sees `--root`.
/// A later `--root` stays in `rest` for the child.
fn parse_roots(
    args: &[String],
    valued: &[&str],
    switches: &[&str],
) -> Result<(PathBuf, Vec<PathBuf>, Vec<String>), String> {
    let mut root = std::env::current_dir().map_err(|e| e.to_string())?;
    let mut extras = Vec::new();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let token = args[i].as_str();
        if token == "--" {
            rest.extend(args[i..].iter().cloned());
            break;
        }
        if token == "--root" {
            root = PathBuf::from(flag_value(args, i, "--root")?);
            i += 2;
            continue;
        }
        if token == "--extra-root" {
            extras.push(PathBuf::from(flag_value(args, i, "--extra-root")?));
            i += 2;
            continue;
        }
        if valued.contains(&token) {
            let value = flag_value(args, i, token)?;
            rest.push(args[i].clone());
            rest.push(value.to_string());
            i += 2;
            continue;
        }
        if switches.contains(&token) {
            rest.push(args[i].clone());
            i += 1;
            continue;
        }
        rest.extend(args[i..].iter().cloned());
        break;
    }
    Ok((root, extras, rest))
}

#[cfg(test)]
mod json_escape_tests {
    use super::json_string;

    #[test]
    fn json_string_escapes_quote_backslash_and_controls() {
        assert_eq!(json_string("say\"hi\\there"), "\"say\\\"hi\\\\there\"");
        assert_eq!(json_string("a\nb\rc\td"), "\"a\\nb\\rc\\td\"");
        assert_eq!(json_string("\u{0001}"), "\"\\u0001\"");
    }
}
