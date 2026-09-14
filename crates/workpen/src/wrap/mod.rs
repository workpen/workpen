//! Process-jail wrap. Feature `nono`.
//!
//! Unix uses pinned nono (Landlock / Seatbelt). Windows uses a
//! write-restricted token. Never grant filesystem root (`/` or a
//! Windows drive root) or the current user's home directory. Inspect
//! [`KernelPolicy::grants`]; do not parse nono internals. Do not call
//! [`KernelPolicy::apply`] from unit tests (`Sandbox::apply_auto` is
//! irreversible). [`KernelPolicy::apply_pre_exec`] only installs a Unix
//! child hook. Hosts that need a jail on every OS call
//! [`KernelPolicy::run_child`], which errors instead of spawning when
//! the kernel cannot apply. The default crate (`default = []`) does not
//! compile this module.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use crate::deny::{DenyPolicy, DestDeny, DestDenyKind, dest_deny_at};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

/// Access granted for one path. Hosts branch on this; do not parse messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelAccess {
    Read,
    ReadWrite,
}

/// One grant we will hand to the kernel backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelGrant {
    pub path: PathBuf,
    pub access: KernelAccess,
}

/// Process-jail policy. Workspace RW, extra roots RW, existing system dirs Read.
///
/// Dest-deny names are a second list, not a grant of `/`. Linux Landlock
/// cannot dest-deny a file inside an allowed tree
/// ([nono #1592](https://github.com/nolabs-ai/nono/discussions/1592)).
/// macOS `run_child` applies Seatbelt `(deny file-read* / file-write*)`
/// literals (and `subpath` for directories) via nono `add_platform_rule`.
/// Linux `run_child` bind-overs dest-deny paths in a private mount ns
/// when unprivileged user namespaces are available. If `unshare` is
/// denied, remount is skipped and Landlock still applies (in-tree
/// dest-deny stays a hole). Windows read deny is a follow-up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelPolicy {
    grants: Vec<KernelGrant>,
    dest_denies: Vec<DestDeny>,
    network_blocked: bool,
}

/// Result of applying the jail. Hosts branch on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelApply {
    /// Kernel jail is active in this process, or hooked/spawned for the child.
    Applied,
    /// Platform has no kernel backend. Userspace dest-deny + PathGuard only.
    UserspaceOnly,
}

#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("kernel wrap root is not usable: {0}")]
    Root(String),
    #[error("kernel wrap refused filesystem root {0}; use a subdirectory, not `/`")]
    FsRoot(PathBuf),
    #[error("kernel wrap refused home directory {0}; use a project subdirectory, not $HOME")]
    Home(PathBuf),
    #[error("kernel wrap apply failed: {0}")]
    Apply(String),
}

/// Whether this OS can apply a kernel jail.
#[must_use]
pub fn kernel_supported() -> bool {
    #[cfg(unix)]
    {
        nono::Sandbox::is_supported()
    }
    #[cfg(windows)]
    {
        windows::write_restricted_supported()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Build a process-jail policy. Does not apply it.
///
/// Refuses filesystem root and the current user's home directory as the
/// workspace. Extra-roots may still be an explicit `/tmp`.
///
/// Dest-deny names default to [`crate::default_secret_denies()`] resolved
/// under the workspace, including hardlink siblings. Hosts match
/// [`crate::DestDenyKind`], not English.
pub fn process_jail(
    workspace: impl AsRef<Path>,
    extra: impl IntoIterator<Item = impl AsRef<Path>>,
) -> Result<KernelPolicy, KernelError> {
    process_jail_with_policy(workspace, extra, &DenyPolicy::default())
}

/// Same as [`process_jail`] with a host [`DenyPolicy`].
pub fn process_jail_with_policy(
    workspace: impl AsRef<Path>,
    extra: impl IntoIterator<Item = impl AsRef<Path>>,
    policy: &DenyPolicy,
) -> Result<KernelPolicy, KernelError> {
    refuse_home_workspace(workspace.as_ref())?;
    let mut grants = Vec::new();
    add_rw(&mut grants, workspace.as_ref())?;
    for extra in extra {
        add_rw(&mut grants, extra.as_ref())?;
    }
    for dir in system_read_dirs() {
        add_read_if_dir(&mut grants, &dir);
    }
    let dest_denies = collect_workspace_dest_denies(workspace.as_ref(), policy)?;
    Ok(KernelPolicy {
        grants,
        dest_denies,
        network_blocked: true,
    })
}

impl KernelPolicy {
    pub fn grants(&self) -> &[KernelGrant] {
        &self.grants
    }

    /// Dest-deny paths collected under the workspace. Not a filesystem grant.
    pub fn dest_denies(&self) -> &[DestDeny] {
        &self.dest_denies
    }

    /// Add host dest-deny paths. Existing files are classified (glob or
    /// hardlink). Missing paths are still recorded as [`DestDenyKind::DenyGlob`].
    pub fn with_dest_deny_paths(
        mut self,
        paths: impl IntoIterator<Item = impl AsRef<Path>>,
    ) -> Self {
        for path in paths {
            push_dest_deny(&mut self.dest_denies, dest_deny_from_path(path.as_ref()));
        }
        self
    }

    /// True when the policy asked the kernel backend to block sockets.
    ///
    /// Unix `run_child` passes this to nono `block_network()`. Windows
    /// write-restricted tokens do not block TCP; this flag is stored
    /// but not enforced there.
    pub fn network_blocked(&self) -> bool {
        self.network_blocked
    }

    /// Apply Landlock/Seatbelt for this process. Irreversible. Not for tests.
    ///
    /// Uses `SignalMode::AllowAll` so a jailed parent can still signal children.
    /// Windows cannot retoken the current process; this stays
    /// [`KernelApply::UserspaceOnly`].
    pub fn apply(&self) -> Result<KernelApply, KernelError> {
        if !kernel_supported() {
            return Ok(KernelApply::UserspaceOnly);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let caps = self.to_capability_set(nono::SignalMode::AllowAll)?;
            nono::Sandbox::apply_auto(&caps).map_err(|e| KernelError::Apply(e.to_string()))?;
            Ok(KernelApply::Applied)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Ok(KernelApply::UserspaceOnly)
        }
    }

    /// Install Landlock/Seatbelt in the child `pre_exec` hook.
    ///
    /// Builds the capability set in the parent (allocation is not safe after
    /// fork). Uses `SignalMode::Isolated` so the child cannot signal the parent.
    /// Does not jail this process. Windows has no `pre_exec`; this stays
    /// [`KernelApply::UserspaceOnly`]. Use [`Self::run_child`] to jail a child.
    pub fn apply_pre_exec(&self, cmd: &mut Command) -> Result<KernelApply, KernelError> {
        if !kernel_supported() {
            let _ = cmd;
            return Ok(KernelApply::UserspaceOnly);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let caps = self.to_capability_set(nono::SignalMode::Isolated)?;
            let dests: Vec<PathBuf> = self.dest_denies.iter().map(|d| d.path.clone()).collect();
            // Safety: the set and dest list are built in the parent; the hook
            // only applies them and maps failure to io::Error.
            unsafe {
                use std::os::unix::process::CommandExt;
                cmd.pre_exec(move || {
                    #[cfg(target_os = "linux")]
                    linux::apply_dest_deny_remounts(&dests)?;
                    #[cfg(not(target_os = "linux"))]
                    let _ = &dests;
                    nono::Sandbox::apply_auto(&caps)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    Ok(())
                });
            }
            Ok(KernelApply::Applied)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = cmd;
            Ok(KernelApply::UserspaceOnly)
        }
    }

    /// Spawn `cmd` under the kernel jail and wait for it.
    ///
    /// Unix installs `pre_exec` then `status`. Windows creates a
    /// write-restricted token and `CreateProcessAsUserW`. If the kernel
    /// cannot apply, this returns [`KernelError::Apply`] and does not
    /// start the child. [`KernelApply::UserspaceOnly`] stays on
    /// [`Self::apply`] / [`Self::apply_pre_exec`] inspect paths only.
    pub fn run_child(&self, cmd: Command) -> Result<(KernelApply, ExitStatus), KernelError> {
        #[cfg(unix)]
        {
            if !kernel_supported() {
                return Err(KernelError::Apply(
                    "kernel jail is not available; child was not started".into(),
                ));
            }
            let mut cmd = cmd;
            scrub_child_command(&mut cmd);
            let applied = require_applied(self.apply_pre_exec(&mut cmd)?)?;
            let status = cmd
                .status()
                .map_err(|e| KernelError::Apply(e.to_string()))?;
            Ok((applied, status))
        }
        #[cfg(windows)]
        {
            if !kernel_supported() {
                return Err(KernelError::Apply(
                    "write-restricted token is not available".into(),
                ));
            }
            windows::spawn_write_restricted(self, &cmd)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = cmd;
            Err(KernelError::Apply(
                "no kernel backend on this platform".into(),
            ))
        }
    }

    #[cfg(unix)]
    fn to_capability_set(
        &self,
        signal: nono::SignalMode,
    ) -> Result<nono::CapabilitySet, KernelError> {
        let mut caps = nono::CapabilitySet::new();
        for grant in &self.grants {
            let mode = match grant.access {
                KernelAccess::Read => nono::AccessMode::Read,
                KernelAccess::ReadWrite => nono::AccessMode::ReadWrite,
            };
            caps = caps
                .allow_path(&grant.path, mode)
                .map_err(|e| KernelError::Apply(e.to_string()))?;
        }
        #[cfg(target_os = "macos")]
        add_macos_dest_deny_rules(&mut caps, &self.dest_denies)?;
        Ok(caps.block_network().set_signal_mode(signal))
    }
}

/// Names `run_child` strips from the child environment.
#[must_use]
pub fn child_env_deny_names() -> &'static [&'static str] {
    &[
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "BASH_ENV",
        "ENV",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "PERL5OPT",
        "XAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
    ]
}

/// True when `name` is on the child-env denylist (ASCII case-insensitive).
#[must_use]
pub fn is_denied_child_env(name: impl AsRef<OsStr>) -> bool {
    let raw = name.as_ref().to_string_lossy();
    child_env_deny_names()
        .iter()
        .any(|n| raw.eq_ignore_ascii_case(n))
}

/// Remove denylist keys from `cmd` so Unix `status` does not inherit them.
pub fn scrub_child_command(cmd: &mut Command) {
    for name in child_env_deny_names() {
        cmd.env_remove(name);
    }
}

/// Insert `--noprofile` and `--norc` after argv0 when the program is bash.
///
/// When argv0 is `env`/`env.exe`, drop `NAME=value` assignments whose name
/// is on the child-env denylist, including leftover tokens inside a `-S` /
/// `--split-string` operand, then insert after the first non-flag operand
/// that is bash. Walks clustered shorts (`-iC /tmp`) and value flags
/// (`-u NAME`, `-f FILE`, `--file FILE`). Attached forms stay one token.
///
/// When argv0 is `timeout`/`nohup`/`nice` (or `.exe`), skip wrapper flags
/// plus the timeout duration or `nice -n N`. If the remaining argv starts
/// with env, drop denylist assignments on that env argv, then insert after
/// the first bash operand (wrapper bash or env bash). Non-bash commands
/// (`timeout 30 echo hi`) stay unchanged.
#[must_use]
pub fn with_bash_noprofile(
    program: impl AsRef<OsStr>,
    args: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> (OsString, Vec<OsString>) {
    let program = program.as_ref().to_os_string();
    let mut args: Vec<OsString> = args
        .into_iter()
        .map(|a| a.as_ref().to_os_string())
        .collect();
    if is_env_argv0(&program) {
        drop_denied_env_assignments(&mut args, 0);
    } else if let Some(kind) = cmd_wrapper(&program) {
        let start = skip_wrapper_os(kind, &args);
        if args.get(start).is_some_and(|a| is_env_argv0(a.as_os_str())) {
            drop_denied_env_assignments(&mut args, start + 1);
        }
    }
    if is_bash_argv0(&program) {
        insert_bash_noprofile(&mut args, 0);
    } else if is_env_argv0(&program)
        && let Some(idx) = first_env_bash_operand(&args)
    {
        insert_bash_noprofile(&mut args, idx + 1);
    } else if let Some(kind) = cmd_wrapper(&program)
        && let Some(idx) = first_wrapper_bash_operand(kind, &args)
    {
        insert_bash_noprofile(&mut args, idx + 1);
    }
    (program, args)
}

fn drop_denied_env_assignments(args: &mut Vec<OsString>, mut i: usize) {
    let mut options_done = false;
    while i < args.len() {
        let raw = args[i].to_string_lossy().into_owned();
        if !options_done {
            if raw == "--" {
                options_done = true;
                i += 1;
                continue;
            }
            if let Some(skip) = env_flag_skip(&raw) {
                rewrite_denied_in_env_s(args, i);
                i = i.saturating_add(skip);
                continue;
            }
        }
        if let Some(eq) = raw.find('=') {
            let name = &raw[..eq];
            if !name.is_empty() && is_denied_child_env(name) {
                args.remove(i);
                continue;
            }
            i += 1;
            continue;
        }
        break;
    }
}

fn rewrite_denied_in_env_s(args: &mut [OsString], i: usize) {
    let raw = args[i].to_string_lossy().into_owned();
    if let Some(value) = raw.strip_prefix("--split-string=") {
        let dropped = drop_denied_from_split_string(value);
        args[i] = OsString::from(format!("--split-string={dropped}"));
        return;
    }
    if raw == "--split-string" {
        rewrite_next_s_operand(args, i);
        return;
    }
    if let Some((prefix, attached)) = env_s_cluster(&raw) {
        if attached.is_empty() {
            rewrite_next_s_operand(args, i);
        } else {
            let dropped = drop_denied_from_split_string(attached);
            args[i] = OsString::from(format!("{prefix}{dropped}"));
        }
    }
}

fn rewrite_next_s_operand(args: &mut [OsString], i: usize) {
    if let Some(op) = args.get_mut(i + 1) {
        let dropped = drop_denied_from_split_string(&op.to_string_lossy());
        *op = OsString::from(dropped);
    }
}

/// Clustered `-*S` / `-S` (not `--`). Prefix includes `S`; rest is attached.
fn env_s_cluster(arg: &str) -> Option<(&str, &str)> {
    if !arg.starts_with('-') || arg.starts_with("--") || arg == "-" {
        return None;
    }
    let rest = &arg[1..];
    let mut idx = 0;
    for c in rest.chars() {
        if c == 'S' {
            let prefix_end = 1 + idx + c.len_utf8();
            return Some((&arg[..prefix_end], &arg[prefix_end..]));
        }
        if crate::deny::env_takes_value(c) {
            return None;
        }
        idx += c.len_utf8();
    }
    None
}

fn drop_denied_from_split_string(s: &str) -> String {
    let tokens: Vec<&str> = s.split_whitespace().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let raw = tokens[i];
        if raw == "--" || raw == "-" {
            out.extend_from_slice(&tokens[i..]);
            break;
        }
        if let Some(skip) = env_flag_skip(raw) {
            let end = (i + skip).min(tokens.len());
            out.extend_from_slice(&tokens[i..end]);
            i = end;
            continue;
        }
        if let Some(eq) = raw.find('=') {
            let name = &raw[..eq];
            if !name.is_empty() && is_denied_child_env(name) {
                i += 1;
                continue;
            }
            out.push(raw);
            i += 1;
            continue;
        }
        out.extend_from_slice(&tokens[i..]);
        break;
    }
    out.join(" ")
}

fn insert_bash_noprofile(args: &mut Vec<OsString>, at: usize) {
    let has_noprofile = args[at..].iter().any(|a| a == "--noprofile");
    let has_norc = args[at..].iter().any(|a| a == "--norc");
    if !has_noprofile {
        args.insert(at, OsString::from("--noprofile"));
    }
    if !has_norc {
        let idx = args[at..]
            .iter()
            .position(|a| a == "--noprofile")
            .map(|i| at + i + 1)
            .unwrap_or(at);
        args.insert(idx, OsString::from("--norc"));
    }
}

fn is_bash_argv0(program: &OsStr) -> bool {
    let raw = program.to_string_lossy();
    let name = raw.rsplit(['/', '\\']).next().unwrap_or(raw.as_ref());
    name.eq_ignore_ascii_case("bash") || name.eq_ignore_ascii_case("bash.exe")
}

fn is_env_argv0(program: &OsStr) -> bool {
    crate::deny::is_env_program(program)
}

fn first_env_bash_operand(args: &[OsString]) -> Option<usize> {
    let mut i = 0;
    while i < args.len() {
        let raw = args[i].to_string_lossy();
        if raw == "--" {
            return args
                .get(i + 1)
                .filter(|a| is_bash_argv0(a.as_os_str()))
                .map(|_| i + 1);
        }
        if let Some(skip) = env_flag_skip(&raw) {
            i = i.saturating_add(skip);
            continue;
        }
        if raw.contains('=') {
            i += 1;
            continue;
        }
        if is_bash_argv0(args[i].as_os_str()) {
            return Some(i);
        }
        return None;
    }
    None
}

fn cmd_wrapper(program: &OsStr) -> Option<crate::deny::CmdWrapper> {
    crate::deny::cmd_wrapper(program)
}

fn skip_wrapper_os(kind: crate::deny::CmdWrapper, args: &[OsString]) -> usize {
    let raws: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    crate::deny::skip_wrapper_prefix(kind, &raws)
}

fn first_wrapper_bash_operand(kind: crate::deny::CmdWrapper, args: &[OsString]) -> Option<usize> {
    let start = skip_wrapper_os(kind, args);
    let rest = args.get(start..)?;
    if rest.first().is_some_and(|a| is_bash_argv0(a.as_os_str())) {
        return Some(start);
    }
    if rest.first().is_some_and(|a| is_env_argv0(a.as_os_str())) {
        return first_env_bash_operand(&rest[1..]).map(|i| start + 1 + i);
    }
    None
}

fn env_flag_skip(arg: &str) -> Option<usize> {
    crate::deny::env_flag_skip(arg)
}

/// Call `spawn` only when token or job setup succeeded.
pub fn spawn_after_setup<T>(
    setup: Result<T, KernelError>,
    spawn: impl FnOnce(T) -> Result<(KernelApply, ExitStatus), KernelError>,
) -> Result<(KernelApply, ExitStatus), KernelError> {
    spawn(setup?)
}

/// Refuse a userspace-only inspect result on the spawn path.
pub fn require_applied(applied: KernelApply) -> Result<KernelApply, KernelError> {
    match applied {
        KernelApply::Applied => Ok(applied),
        KernelApply::UserspaceOnly => Err(KernelError::Apply(
            "kernel jail did not apply; child was not started".into(),
        )),
    }
}

const DEST_DENY_WALK_LIMIT: usize = 65_536;

/// Existing dest-deny files under `workspace`, including hardlink siblings.
///
/// Does not apply the jail. Does not follow directory symlinks. Walk
/// failure or an entry cap is [`KernelError::Root`].
pub fn collect_workspace_dest_denies(
    workspace: &Path,
    policy: &DenyPolicy,
) -> Result<Vec<DestDeny>, KernelError> {
    let mut out = Vec::new();
    let mut remaining = DEST_DENY_WALK_LIMIT;
    walk_dest_denies(workspace, policy, &mut out, &mut remaining)?;
    Ok(out)
}

fn walk_dest_denies(
    dir: &Path,
    policy: &DenyPolicy,
    out: &mut Vec<DestDeny>,
    remaining: &mut usize,
) -> Result<(), KernelError> {
    if *remaining == 0 {
        return Err(KernelError::Root(format!(
            "dest-deny walk exceeded {DEST_DENY_WALK_LIMIT} entries under {}",
            dir.display()
        )));
    }
    let rd = std::fs::read_dir(dir)
        .map_err(|e| KernelError::Root(format!("dest-deny walk {}: {e}", dir.display())))?;
    for ent in rd {
        if *remaining == 0 {
            return Err(KernelError::Root(format!(
                "dest-deny walk exceeded {DEST_DENY_WALK_LIMIT} entries under {}",
                dir.display()
            )));
        }
        *remaining -= 1;
        let ent =
            ent.map_err(|e| KernelError::Root(format!("dest-deny walk {}: {e}", dir.display())))?;
        let path = ent.path();
        let ft = ent
            .file_type()
            .map_err(|e| KernelError::Root(format!("dest-deny walk {}: {e}", path.display())))?;
        if ft.is_dir() && !ft.is_symlink() {
            walk_dest_denies(&path, policy, out, remaining)?;
            continue;
        }
        if let Some(deny) = dest_deny_at(&path, path.display().to_string(), policy) {
            push_dest_deny(out, deny);
        }
    }
    Ok(())
}

fn dest_deny_from_path(path: &Path) -> DestDeny {
    dest_deny_at(path, path.display().to_string(), &DenyPolicy::default()).unwrap_or(DestDeny {
        kind: DestDenyKind::DenyGlob,
        path: path.to_path_buf(),
        display: path.display().to_string(),
        matched: None,
    })
}

fn push_dest_deny(out: &mut Vec<DestDeny>, deny: DestDeny) {
    if out
        .iter()
        .any(|d| d.path == deny.path && d.kind == deny.kind)
    {
        return;
    }
    out.push(deny);
}

/// Seatbelt dest-deny of workspace secrets. Platform rules emit last so
/// they win over the workspace ReadWrite allow (nono last-rule-wins).
/// Do not use `require-not` inside deny (invalid SBPL).
#[cfg(target_os = "macos")]
fn add_macos_dest_deny_rules(
    caps: &mut nono::CapabilitySet,
    denies: &[DestDeny],
) -> Result<(), KernelError> {
    for deny in denies {
        for path in dest_deny_rule_paths(&deny.path) {
            let Some(raw) = path.to_str() else {
                return Err(KernelError::Apply(format!(
                    "dest-deny path is not UTF-8: {}",
                    path.display()
                )));
            };
            let escaped = escape_sbpl_literal(raw);
            let filter = if path.is_dir() {
                format!("subpath \"{escaped}\"")
            } else {
                format!("literal \"{escaped}\"")
            };
            for action in ["file-read*", "file-write*"] {
                let rule = format!("(deny {action} ({filter}))");
                caps.add_platform_rule(&rule)
                    .map_err(|e| KernelError::Apply(e.to_string()))?;
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn dest_deny_rule_paths(path: &Path) -> Vec<PathBuf> {
    let mut out = vec![path.to_path_buf()];
    if let Ok(canon) = dunce::canonicalize(path)
        && canon != path
    {
        out.push(canon);
    }
    out
}

#[cfg(target_os = "macos")]
fn escape_sbpl_literal(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn refuse_home_workspace(workspace: &Path) -> Result<(), KernelError> {
    let resolved = match std::fs::canonicalize(workspace) {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };
    if crate::guard::is_user_home_dir(&resolved) {
        return Err(KernelError::Home(resolved));
    }
    Ok(())
}

fn system_read_dirs() -> Vec<PathBuf> {
    #[cfg(unix)]
    {
        [
            "/usr",
            "/bin",
            "/lib",
            "/lib64",
            "/sbin",
            "/System",
            "/Library",
            "/dev",
            "/etc",
            "/opt/homebrew",
            "/usr/local",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect()
    }
    #[cfg(windows)]
    {
        let mut dirs = Vec::new();
        if let Some(root) = std::env::var_os("SystemRoot") {
            let root = PathBuf::from(root);
            dirs.push(root.join("System32"));
            dirs.push(root);
        }
        if let Some(pf) = std::env::var_os("ProgramFiles") {
            dirs.push(PathBuf::from(pf));
        }
        dirs
    }
    #[cfg(not(any(unix, windows)))]
    {
        Vec::new()
    }
}

fn add_rw(grants: &mut Vec<KernelGrant>, path: &Path) -> Result<(), KernelError> {
    let resolved = canonicalize_dir(path)?;
    // Grant the path as given so symlink lookups (`/tmp` -> `/private/tmp`) work.
    if !is_fs_root(path) && path != resolved.as_path() {
        push_grant(grants, path.to_path_buf(), KernelAccess::ReadWrite);
    }
    push_grant(grants, resolved, KernelAccess::ReadWrite);
    Ok(())
}

fn add_read_if_dir(grants: &mut Vec<KernelGrant>, path: &Path) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }
    let resolved = std::fs::canonicalize(path).ok();
    if resolved.as_ref().is_some_and(|p| is_fs_root(p)) {
        return;
    }
    // Grant the path as given so symlink lookups (`/etc` -> `/private/etc`) work.
    if !is_fs_root(path) {
        push_grant(grants, path.to_path_buf(), KernelAccess::Read);
    }
    if let Some(resolved) = resolved {
        push_grant(grants, resolved, KernelAccess::Read);
    }
}

fn push_grant(grants: &mut Vec<KernelGrant>, path: PathBuf, access: KernelAccess) {
    if let Some(existing) = grants.iter_mut().find(|g| g.path == path) {
        if access == KernelAccess::ReadWrite {
            existing.access = KernelAccess::ReadWrite;
        }
        return;
    }
    grants.push(KernelGrant { path, access });
}

fn canonicalize_dir(path: &Path) -> Result<PathBuf, KernelError> {
    let resolved = std::fs::canonicalize(path)
        .map_err(|e| KernelError::Root(format!("{}: {e}", path.display())))?;
    if !resolved.is_dir() {
        return Err(KernelError::Root(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    if is_fs_root(&resolved) {
        return Err(KernelError::FsRoot(resolved));
    }
    Ok(resolved)
}

fn is_fs_root(path: &Path) -> bool {
    match path.parent() {
        None => true,
        Some(parent) => parent.as_os_str().is_empty(),
    }
}
