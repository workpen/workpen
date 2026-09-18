//! Dest-deny predicate. Glob match, hardlink sibling, patch dests, argv tokens.

use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::agent_lock::{AgentLockError, load_agent_lock};
use crate::guard::{PathGuard, PathGuardError};

/// Portable dest-deny policy. Same globs on every OS.
/// Hosts hold this value. There is no process-wide default slot. Clone is cheap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyPolicy {
    globs: Arc<Vec<String>>,
}

impl Default for DenyPolicy {
    fn default() -> Self {
        Self {
            globs: Arc::new(default_secret_denies()),
        }
    }
}

impl DenyPolicy {
    pub fn new(globs: Vec<String>) -> Self {
        Self {
            globs: Arc::new(globs),
        }
    }

    /// Intern a host-held glob list. Does not copy the strings.
    /// There is still no process-wide deny slot.
    pub fn from_arc(globs: Arc<Vec<String>>) -> Self {
        Self { globs }
    }

    /// Same allocation as [`DenyPolicy::from_arc`] / clone.
    pub fn globs_arc(&self) -> Arc<Vec<String>> {
        Arc::clone(&self.globs)
    }

    /// `default_secret_denies()` plus extras. Extras never replace defaults.
    pub fn with_extra(extra: impl IntoIterator<Item = String>) -> Self {
        let mut globs = default_secret_denies();
        for g in extra {
            if !globs.iter().any(|x| x == &g) {
                globs.push(g);
            }
        }
        Self {
            globs: Arc::new(globs),
        }
    }

    /// Defaults plus workspace `agent.lock` extras. Missing lock equals default.
    /// Extras never replace defaults. Invalid lock is [`AgentLockError`].
    pub fn from_workspace(path: impl AsRef<Path>) -> Result<Self, AgentLockError> {
        Ok(Self::with_extra(load_agent_lock(path.as_ref())?))
    }

    pub fn globs(&self) -> &[String] {
        &self.globs
    }
}

/// Why dest-deny rejected a path. Hosts branch on this; do not parse messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestDenyKind {
    /// Basename or full path matched a deny glob (raw or canonical).
    DenyGlob,
    /// Another directory entry shares this inode / NTFS file index and is denied.
    HardlinkSibling,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestDeny {
    pub kind: DestDenyKind,
    pub path: PathBuf,
    pub display: String,
    /// Matching deny glob, or the other hardlink's basename.
    pub matched: Option<String>,
}

impl DestDeny {
    /// Wording distinguishes glob vs hardlink.
    /// Hardlink must not say "matches deny glob".
    pub fn message(&self) -> String {
        match (&self.kind, self.matched.as_deref()) {
            (DestDenyKind::DenyGlob, Some(glob)) => format!(
                "path denied by sandbox profile (matches deny glob {glob}): {}",
                self.display
            ),
            (DestDenyKind::DenyGlob, None) => format!(
                "path denied by sandbox profile (matches deny glob): {}",
                self.display
            ),
            (DestDenyKind::HardlinkSibling, Some(sib)) => format!(
                "path denied by sandbox profile (hardlink of a denied name {sib}): {}",
                self.display
            ),
            (DestDenyKind::HardlinkSibling, None) => format!(
                "path denied by sandbox profile (hardlink of a denied name): {}",
                self.display
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DestDenyError {
    #[error("{0}")]
    Denied(DestDeny),
    /// Argv token hit. Distinct wording from [`DestDeny::message`].
    #[error("command references path denied by sandbox profile: {token}")]
    CommandToken { token: String },
    /// PowerShell `-EncodedCommand` payload is not UTF-16LE RFC 4648.
    #[error("invalid -EncodedCommand payload (need UTF-16LE base64); child was not started")]
    EncodedCommand,
    /// PowerShell `-Command -` / `-File -` (and unique prefixes), or positional `-`, read a script from stdin.
    #[error(
        "PowerShell stdin script (-Command - or -File -) cannot be dest-denied; child was not started"
    )]
    StdinScript,
    /// Post-open hardlink hit. Distinct wording from [`DestDeny::message`].
    #[error(
        "path denied: {path} is a hardlink of a denied name; unlink extra names or do not share the inode"
    )]
    LateHardlink { path: String },
    /// Path identity changed between check and open.
    #[error("TOCTOU race detected: {path} changed between check and open")]
    Toctou { path: String },
    #[error("TOCTOU check failed: {0}")]
    ToctouStat(String),
}

/// Host composition error. Dest-deny vs PathGuard; do not parse messages.
#[derive(Debug, thiserror::Error)]
pub enum CheckDestError {
    #[error(transparent)]
    DestDeny(#[from] DestDenyError),
    #[error(transparent)]
    PathGuard(#[from] PathGuardError),
    #[error("path contains a NUL byte")]
    Nul,
    #[error("refuse special file ({kind}): {path}")]
    SpecialFile { path: String, kind: &'static str },
    /// Read helper only. [`check_dest`] still allows directories.
    #[error("refuse directory read: {path}")]
    Directory { path: String },
    #[error("open failed: {0}")]
    Io(String),
}

impl std::fmt::Display for DestDeny {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

/// Classify one dest. Glob vs hardlink only. Does not jail `..`.
pub fn classify_dest(path: &Path, policy: &DenyPolicy) -> Option<DestDenyKind> {
    classify_dest_hit(path, policy).map(|hit| hit.kind)
}

struct DestDenyHit {
    kind: DestDenyKind,
    matched: Option<String>,
}

fn classify_dest_hit(path: &Path, policy: &DenyPolicy) -> Option<DestDenyHit> {
    if let Some(glob) = first_matching_deny_glob(policy.globs(), &path_as_glob(path)) {
        return Some(DestDenyHit {
            kind: DestDenyKind::DenyGlob,
            matched: Some(glob),
        });
    }

    let canon = std::fs::canonicalize(path).ok();
    if let Some(canon) = &canon
        && let Some(glob) = first_matching_deny_glob(policy.globs(), &path_as_glob(canon))
    {
        return Some(DestDenyHit {
            kind: DestDenyKind::DenyGlob,
            matched: Some(glob),
        });
    }
    match hardlink_sibling_hit(path, canon.as_deref(), policy) {
        HardlinkHit::Denied { sibling } => Some(DestDenyHit {
            kind: DestDenyKind::HardlinkSibling,
            matched: sibling,
        }),
        HardlinkHit::Allowed => None,
    }
}

pub(crate) fn dest_deny_at(
    classified: &Path,
    display: String,
    policy: &DenyPolicy,
) -> Option<DestDeny> {
    classify_dest_hit(classified, policy).map(|hit| DestDeny {
        kind: hit.kind,
        path: classified.to_path_buf(),
        display,
        matched: hit.matched,
    })
}

pub fn is_path_denied(path: &Path, policy: &DenyPolicy) -> bool {
    classify_dest(path, policy).is_some()
}

pub fn dest_deny_message(path: &Path, display: &str, policy: &DenyPolicy) -> Option<String> {
    dest_deny_at(path, display.to_owned(), policy).map(|d| d.message())
}

/// Dest-deny raw; if `guard` is `Some`, PathGuard; dest-deny resolved.
///
/// `guard: None` dest-denies raw and, if the path exists, dest-denies the
/// cwd-joined canonicalize. Does not treat cwd as a workspace root.
/// Rejects NUL and existing fifo / socket / device. Does not peel.
/// Does not refuse directories (write dests). See [`open_verified_read`].
pub fn check_dest(
    path: &str,
    policy: &DenyPolicy,
    guard: Option<&PathGuard>,
) -> Result<PathBuf, CheckDestError> {
    if path.contains('\0') {
        return Err(CheckDestError::Nul);
    }
    let raw = Path::new(path);
    if let Some(deny) = dest_deny_at(raw, path.to_owned(), policy) {
        return Err(CheckDestError::DestDeny(DestDenyError::Denied(deny)));
    }

    let resolved = match guard {
        Some(g) => g.check(raw)?,
        None => {
            let joined = if raw.is_absolute() {
                raw.to_path_buf()
            } else {
                match std::env::current_dir() {
                    Ok(cwd) => cwd.join(raw),
                    Err(_) => raw.to_path_buf(),
                }
            };
            if joined.exists() {
                std::fs::canonicalize(&joined).unwrap_or(joined)
            } else {
                joined
            }
        }
    };

    if let Some(deny) = dest_deny_at(&resolved, path.to_owned(), policy) {
        return Err(CheckDestError::DestDeny(DestDenyError::Denied(deny)));
    }
    reject_special_file(&resolved)?;
    Ok(resolved)
}

/// `check_dest`, refuse directories, open for read, then [`verify_post_open`].
pub fn open_verified_read(
    path: &str,
    policy: &DenyPolicy,
    guard: Option<&PathGuard>,
) -> Result<File, CheckDestError> {
    let resolved = check_dest(path, policy, guard)?;
    refuse_directory(&resolved)?;
    let file = File::open(&resolved).map_err(|e| CheckDestError::Io(e.to_string()))?;
    if file.metadata().map(|m| m.is_dir()).unwrap_or(false) {
        return Err(directory_read_error(&resolved));
    }
    verify_post_open(&resolved, &file, policy)?;
    Ok(file)
}

fn refuse_directory(path: &Path) -> Result<(), CheckDestError> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Ok(());
    };
    if meta.is_dir() {
        return Err(directory_read_error(path));
    }
    Ok(())
}

fn directory_read_error(path: &Path) -> CheckDestError {
    CheckDestError::Directory {
        path: path.display().to_string(),
    }
}

fn reject_special_file(path: &Path) -> Result<(), CheckDestError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let Ok(meta) = std::fs::metadata(path) else {
            return Ok(());
        };
        let ft = meta.file_type();
        let kind = if ft.is_fifo() {
            Some("fifo")
        } else if ft.is_socket() {
            Some("socket")
        } else if ft.is_char_device() || ft.is_block_device() {
            Some("device")
        } else {
            None
        };
        if let Some(kind) = kind {
            return Err(CheckDestError::SpecialFile {
                path: path.display().to_string(),
                kind,
            });
        }
    }
    let _ = path;
    Ok(())
}

/// Unix inode/dev; Windows file index + volume serial.
/// Re-runs hardlink dest-deny when nlink / nNumberOfLinks > 1.
pub fn verify_post_open(path: &Path, fd: &File, policy: &DenyPolicy) -> Result<(), DestDenyError> {
    #[cfg(unix)]
    {
        verify_post_open_unix(path, fd, policy)
    }
    #[cfg(windows)]
    {
        verify_post_open_windows(path, fd, policy)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, fd, policy);
        Ok(())
    }
}

#[cfg(unix)]
fn verify_post_open_unix(path: &Path, fd: &File, policy: &DenyPolicy) -> Result<(), DestDenyError> {
    use std::os::unix::fs::MetadataExt;

    let path_meta = std::fs::symlink_metadata(path)
        .map_err(|e| DestDenyError::ToctouStat(format!("cannot stat {}: {e}", path.display())))?;
    let fd_meta = fd
        .metadata()
        .map_err(|e| DestDenyError::ToctouStat(format!("cannot fstat fd: {e}")))?;
    if path_meta.ino() != fd_meta.ino() || path_meta.dev() != fd_meta.dev() {
        return Err(DestDenyError::Toctou {
            path: path.display().to_string(),
        });
    }
    if fd_meta.nlink() > 1 {
        let canon = std::fs::canonicalize(path).ok();
        if hardlink_sibling_denied(path, canon.as_deref(), policy) {
            return Err(DestDenyError::LateHardlink {
                path: path.display().to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(windows)]
fn verify_post_open_windows(
    path: &Path,
    fd: &File,
    policy: &DenyPolicy,
) -> Result<(), DestDenyError> {
    use std::os::windows::io::AsRawHandle;

    let path_info = win_path_by_handle(path)
        .map_err(|e| DestDenyError::ToctouStat(format!("cannot stat {}: {e}", path.display())))?;
    let fd_info = win_handle_info(fd.as_raw_handle())
        .map_err(|e| DestDenyError::ToctouStat(format!("cannot fstat fd: {e}")))?;
    if path_info.index != fd_info.index || path_info.volume != fd_info.volume {
        return Err(DestDenyError::Toctou {
            path: path.display().to_string(),
        });
    }
    if fd_info.nlink > 1 {
        let canon = std::fs::canonicalize(path).ok();
        if hardlink_sibling_denied(path, canon.as_deref(), policy) {
            return Err(DestDenyError::LateHardlink {
                path: path.display().to_string(),
            });
        }
    }
    Ok(())
}

/// Refuse if any host-extracted dest is a secret glob or hardlink sibling.
///
/// Does not check out-of-tree. Hosts then run PathGuard on the same dests.
pub fn deny_patch_dests(
    dests: &[impl AsRef<Path>],
    policy: &DenyPolicy,
) -> Result<(), DestDenyError> {
    for dest in dests {
        let dest = dest.as_ref();
        if let Some(deny) = dest_deny_at(dest, dest.display().to_string(), policy) {
            return Err(DestDenyError::Denied(deny));
        }
    }
    Ok(())
}

/// Like [`deny_patch_dests`], with a host-chosen display string per dest.
pub fn deny_patch_dests_with_display(
    dests: &[(&Path, &str)],
    policy: &DenyPolicy,
) -> Result<(), DestDenyError> {
    for (dest, display) in dests {
        if let Some(deny) = dest_deny_at(dest, (*display).to_owned(), policy) {
            return Err(DestDenyError::Denied(deny));
        }
    }
    Ok(())
}

/// Argv / command token scan. Does not parse a full shell.
pub fn reject_command_secret_path_tokens(
    command: &str,
    policy: &DenyPolicy,
) -> Result<(), DestDenyError> {
    for (display, candidate) in command_path_tokens(command) {
        if candidate_is_denied(&candidate, policy) {
            return Err(DestDenyError::CommandToken { token: display });
        }
    }
    Ok(())
}

/// Join a relative dest to `root`. Absolute dests stay as given.
pub fn dest_under_root(root: &Path, path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}

/// Script body after a shell `-c` cluster (`-c`, `-lc`, `-ic`) or `-cBODY`.
///
/// Cluster letters are the usual bash short options that combine with
/// `-c`. A long word such as `-color` is not a cluster.
fn shell_c_body<'a>(token: &'a str, next: Option<&'a str>) -> Option<&'a str> {
    let rest = token.strip_prefix('-')?;
    if rest.starts_with('-') {
        return None;
    }
    if is_shell_c_cluster(rest) {
        return next;
    }
    let c_at = rest.find('c')?;
    let prefix = rest.get(..=c_at)?;
    if !is_shell_c_cluster(prefix) {
        return None;
    }
    let after = rest.get(c_at + 1..)?;
    if after.is_empty() {
        return next;
    }
    Some(after)
}

fn is_shell_c_cluster(rest: &str) -> bool {
    let len = rest.len();
    // `-cwa` is pwsh -CommandWithArgs, not a bash short-option cluster.
    if rest.eq_ignore_ascii_case("cwa") {
        return false;
    }
    (1..=4).contains(&len) && rest.contains('c') && rest.chars().all(|ch| ch.is_ascii_alphabetic())
}

/// Dest-deny each raw argv dest under `root`.
///
/// Empty and flag-looking tokens are skipped. A shell `-c` token, including
/// short-option clusters that contain `c` (`-lc`, `-ic`, `-lic`, `-cl`)
/// and an attached `-cBODY`, dest-denies paths inside the script body
/// via [`check_command_dests`]. When that body (or any peeled command
/// string) contains an `env`/`env.exe` token, dest-denies the following
/// tokens with the same env-flag dest check used for argv0 env.
/// When argv0 is `env`/`env.exe`, dest-denies the operand of
/// `-S`/`--split-string` via [`check_command_dests`], then leftover
/// tokens in that string as env flags (`--file=`, `-f`, `NAME=value`).
/// After skipping stacked `timeout`/`nohup`/`nice` prefixes (same skip as
/// wrap), dest-denies those env flags when the remaining argv starts with
/// env. A nested `env` operand (or `env -- env …`) is walked the same way.
/// `cmd /c` and `powershell -Command` / `-EncodedCommand` bodies are
/// dest-denied as command strings. After `cmd` / `pwsh`, remaining
/// argv is walked so `/s` / `-NoProfile` cannot hide `/c`,
/// `-EncodedCommand`, `-EncodedArguments`, or `-File`. Unique prefixes
/// (`-en`, `-comma`, `-cwa`) match. A second leading `-`/`/` is stripped
/// (`--Command`, `--EncodedCommand`, `--File`). `-File` / `-f` / `/File`
/// (and `-File:…`) dest-deny the script path. `pwsh -Command -`,
/// `pwsh -File -` (including `--switch` and unique prefixes), and
/// positional `pwsh -` / `powershell -` are
/// [`DestDenyError::StdinScript`]: dest-deny does not read host stdin.
/// `cmd /c -` is unchanged. Those bodies are also peeled
/// inside a shell `-c` string. Generic `/c`, `-Command`, `-EncodedCommand`,
/// `-cwa`, or `-File` on another argv0 is not.
/// Dest-denies argv `-f`/`--file` (including attached `--file=.env`) via
/// [`check_dest`]. Does not dest-deny a flattened join of all argv. Does
/// not peel generic `--flag=.env`.
pub fn check_command_argv(
    cmd: &[impl AsRef<str>],
    root: &Path,
    policy: &DenyPolicy,
) -> Result<(), CheckDestError> {
    for (i, token) in cmd.iter().enumerate() {
        let token = token.as_ref();
        if !token.is_empty() && !token.starts_with('-') {
            let dest = dest_under_root(root, token);
            check_dest(&dest.to_string_lossy(), policy, None)?;
        }
        if let Some(body) = shell_c_body(token, cmd.get(i + 1).map(|s| s.as_ref())) {
            check_command_dests(body, root, policy)?;
        }
        if is_cmd_program(token) || is_powershell_program(token) {
            check_cmd_powershell_remaining_dests(token, &cmd[i + 1..], root, policy)?;
        }
    }
    let start = skip_all_wrappers(cmd);
    if cmd.get(start).is_some_and(|t| is_env_program(t.as_ref())) {
        check_env_flag_dests(&cmd[start + 1..], root, policy)?;
    }
    Ok(())
}

pub(crate) fn is_env_program(program: impl AsRef<OsStr>) -> bool {
    let raw = program.as_ref().to_string_lossy();
    let name = program_basename(&raw);
    name.eq_ignore_ascii_case("env") || name.eq_ignore_ascii_case("env.exe")
}

fn program_basename(program: &str) -> &str {
    program.rsplit(['/', '\\']).next().unwrap_or(program)
}

fn is_cmd_program(program: &str) -> bool {
    let name = program_basename(program);
    name.eq_ignore_ascii_case("cmd") || name.eq_ignore_ascii_case("cmd.exe")
}

fn is_powershell_program(program: &str) -> bool {
    let name = program_basename(program);
    name.eq_ignore_ascii_case("powershell")
        || name.eq_ignore_ascii_case("powershell.exe")
        || name.eq_ignore_ascii_case("pwsh")
        || name.eq_ignore_ascii_case("pwsh.exe")
}

/// `cmd /c` / `/k` script body (`/c`, `/C`, `/kBODY`).
fn cmd_script_body<'a>(token: &'a str, next: Option<&'a str>) -> Option<&'a str> {
    let rest = token.strip_prefix('/')?;
    let first = rest.chars().next()?;
    if !matches!(first, 'c' | 'C' | 'k' | 'K') {
        return None;
    }
    let after = rest.get(first.len_utf8()..)?;
    if after.is_empty() {
        return next;
    }
    Some(after)
}

/// Strip one or two leading `-`/`/` from a PowerShell host switch.
/// `--Command` and `/Command` both yield `Command`.
fn strip_ps_switch(token: &str) -> Option<&str> {
    let rest = token.strip_prefix(['-', '/'])?;
    Some(rest.strip_prefix(['-', '/']).unwrap_or(rest))
}

/// PowerShell `-Command` / `-c` / `/C` / `-cwa` / `-CommandWithArgs` script
/// body, including attached `-Command:…` and unique prefixes (`-comm`).
/// Not `-EncodedCommand` (see [`powershell_encoded_payload`]).
fn powershell_command_body<'a>(token: &'a str, next: Option<&'a str>) -> Option<&'a str> {
    let rest = strip_ps_switch(token)?;
    if let Some((name, value)) = rest.split_once(':') {
        if is_powershell_command_name(name) {
            return Some(value);
        }
        return None;
    }
    if is_powershell_command_name(rest) {
        return next;
    }
    None
}

/// PowerShell `-EncodedCommand` / `-enc` / `-ec` / `-en` / `-e` payload, including
/// attached `-EncodedCommand:…` and unique prefixes (`-en`). Not `-Command`.
fn powershell_encoded_payload<'a>(token: &'a str, next: Option<&'a str>) -> Option<&'a str> {
    let rest = strip_ps_switch(token)?;
    if let Some((name, value)) = rest.split_once(':') {
        if is_powershell_encoded_command_name(name) {
            return Some(value);
        }
        return None;
    }
    if is_powershell_encoded_command_name(rest) {
        return next;
    }
    None
}

/// PowerShell `-EncodedArguments` / `-ea` payload, including attached
/// `-EncodedArguments:…`. Unique prefixes of `encodedarguments` that are
/// not prefixes of `encodedcommand` (`-encodeda`). Host `-ea` is this
/// switch, not `-ErrorAction`.
fn powershell_encoded_arguments_payload<'a>(
    token: &'a str,
    next: Option<&'a str>,
) -> Option<&'a str> {
    let rest = strip_ps_switch(token)?;
    if let Some((name, value)) = rest.split_once(':') {
        if is_powershell_encoded_arguments_name(name) {
            return Some(value);
        }
        return None;
    }
    if is_powershell_encoded_arguments_name(rest) {
        return next;
    }
    None
}

fn is_powershell_encoded_command_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "encodedcommand"
        || lower == "enc"
        || lower == "ec"
        || lower == "e"
        || ("encodedcommand".starts_with(&lower)
            && !"erroraction".starts_with(&lower)
            && !"errorvariable".starts_with(&lower)
            && !"executionpolicy".starts_with(&lower))
}

/// PowerShell `-File` / `-f` / `/File` script dest, including attached
/// `-File:…` / `-f:…` and unique prefixes (`-fi`, `-fil`).
fn powershell_file_dest<'a>(token: &'a str, next: Option<&'a str>) -> Option<&'a str> {
    let rest = strip_ps_switch(token)?;
    if let Some((name, value)) = rest.split_once(':') {
        if is_powershell_file_name(name) {
            return Some(value);
        }
        return None;
    }
    if is_powershell_file_name(rest) {
        return next;
    }
    None
}

fn is_powershell_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "file" || lower == "f" || (lower.len() >= 2 && "file".starts_with(&lower))
}

fn is_powershell_command_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "command"
        || lower == "c"
        || (lower.len() >= 4 && "command".starts_with(&lower))
        || lower == "commandwithargs"
        || lower == "cwa"
        || (lower.len() >= 8 && "commandwithargs".starts_with(&lower))
}

fn is_powershell_encoded_arguments_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "encodedarguments"
        || lower == "ea"
        || ("encodedarguments".starts_with(&lower) && !"encodedcommand".starts_with(&lower))
}

/// After `cmd` / `pwsh`, walk remaining tokens. First `/c`/`/k`,
/// `-EncodedCommand`, `-EncodedArguments`, `-File`, or `-Command`
/// (including `--switch` and unique prefixes) wins. A leftover
/// operand that is exactly `-` is positional File-from-stdin.
fn check_cmd_powershell_remaining_dests(
    program: &str,
    rest: &[impl AsRef<str>],
    root: &Path,
    policy: &DenyPolicy,
) -> Result<(), CheckDestError> {
    if is_cmd_program(program) {
        for (j, token) in rest.iter().enumerate() {
            if let Some(body) = cmd_script_body(token.as_ref(), rest.get(j + 1).map(|s| s.as_ref()))
            {
                return check_command_dests(body, root, policy);
            }
        }
    }
    if is_powershell_program(program) {
        for (j, token) in rest.iter().enumerate() {
            if let Some(payload) =
                powershell_encoded_payload(token.as_ref(), rest.get(j + 1).map(|s| s.as_ref()))
            {
                return check_powershell_encoded_dests(payload, root, policy);
            }
            if let Some(payload) = powershell_encoded_arguments_payload(
                token.as_ref(),
                rest.get(j + 1).map(|s| s.as_ref()),
            ) {
                return check_powershell_encoded_dests(payload, root, policy);
            }
            if let Some(path) =
                powershell_file_dest(token.as_ref(), rest.get(j + 1).map(|s| s.as_ref()))
            {
                refuse_powershell_stdin_dash(path)?;
                let dest = dest_under_root(root, path);
                return check_dest(&dest.to_string_lossy(), policy, None).map(|_| ());
            }
            if let Some(body) =
                powershell_command_body(token.as_ref(), rest.get(j + 1).map(|s| s.as_ref()))
            {
                refuse_powershell_stdin_dash(body)?;
                return check_command_dests(body, root, policy);
            }
        }
        // File is the default positional. `pwsh -` reads a script from stdin.
        for token in rest {
            if token.as_ref() == "-" {
                return Err(DestDenyError::StdinScript.into());
            }
        }
    }
    Ok(())
}

fn refuse_powershell_stdin_dash(body: &str) -> Result<(), CheckDestError> {
    if body == "-" {
        return Err(DestDenyError::StdinScript.into());
    }
    Ok(())
}

/// Decode `-EncodedCommand` UTF-16LE base64 and dest-deny the script.
/// Invalid payloads fail closed as [`DestDenyError::EncodedCommand`].
fn check_powershell_encoded_dests(
    payload: &str,
    root: &Path,
    policy: &DenyPolicy,
) -> Result<(), CheckDestError> {
    let script = decode_powershell_encoded_command(payload).ok_or(DestDenyError::EncodedCommand)?;
    check_command_dests(&script, root, policy)
}

/// RFC 4648 base64 of UTF-16LE. Fail-closed on empty, invalid alphabet,
/// leftover bits, odd length, or unpaired surrogates.
fn decode_powershell_encoded_command(payload: &str) -> Option<String> {
    let stripped: String = payload
        .chars()
        .filter(|c| !matches!(*c, ' ' | '\t' | '\r' | '\n'))
        .collect();
    if stripped.is_empty() {
        return None;
    }
    let bytes = decode_rfc4648_base64(stripped.as_bytes())?;
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

fn decode_rfc4648_base64(input: &[u8]) -> Option<Vec<u8>> {
    fn digit(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let mut pad = 0usize;
    let mut end = input.len();
    while end > 0 && input[end - 1] == b'=' {
        pad += 1;
        end -= 1;
        if pad > 2 {
            return None;
        }
    }
    if input[..end].contains(&b'=') {
        return None;
    }
    if end % 4 == 1 {
        return None;
    }

    let mut out = Vec::with_capacity(end * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in &input[..end] {
        let v = u32::from(digit(b)?);
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return None;
    }
    Some(out)
}

/// Skip stacked `timeout` / `nohup` / `nice` prefixes. Returns the index
/// of the first remaining operand (env, the user command, or `cmd.len()`).
fn skip_all_wrappers(cmd: &[impl AsRef<str>]) -> usize {
    let mut i = 0;
    while i < cmd.len() {
        let Some(kind) = cmd_wrapper(cmd[i].as_ref()) else {
            return i;
        };
        let start = skip_wrapper_prefix(kind, &cmd[i + 1..]);
        i = i.saturating_add(1).saturating_add(start);
    }
    i
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CmdWrapper {
    Timeout,
    Nohup,
    Nice,
}

pub(crate) fn cmd_wrapper(program: impl AsRef<OsStr>) -> Option<CmdWrapper> {
    let raw = program.as_ref().to_string_lossy();
    let name = raw.rsplit(['/', '\\']).next().unwrap_or(raw.as_ref());
    if name.eq_ignore_ascii_case("timeout") || name.eq_ignore_ascii_case("timeout.exe") {
        Some(CmdWrapper::Timeout)
    } else if name.eq_ignore_ascii_case("nohup") || name.eq_ignore_ascii_case("nohup.exe") {
        Some(CmdWrapper::Nohup)
    } else if name.eq_ignore_ascii_case("nice") || name.eq_ignore_ascii_case("nice.exe") {
        Some(CmdWrapper::Nice)
    } else {
        None
    }
}

/// Skip timeout/nohup/nice flags plus the timeout duration. Returns the
/// index of the first remaining command operand.
pub(crate) fn skip_wrapper_prefix(kind: CmdWrapper, args: &[impl AsRef<str>]) -> usize {
    let mut i = 0;
    let mut options_done = false;
    let mut skip_timeout_duration = kind == CmdWrapper::Timeout;
    while i < args.len() {
        let raw = args[i].as_ref();
        if !options_done {
            if raw == "--" {
                options_done = true;
                i += 1;
                continue;
            }
            if let Some(skip) = wrapper_flag_skip(kind, raw) {
                i = i.saturating_add(skip);
                continue;
            }
        }
        if skip_timeout_duration {
            skip_timeout_duration = false;
            i += 1;
            continue;
        }
        return i;
    }
    i
}

fn wrapper_takes_value(kind: CmdWrapper, flag: char) -> bool {
    match kind {
        CmdWrapper::Timeout => matches!(flag, 's' | 'k'),
        CmdWrapper::Nice => flag == 'n',
        CmdWrapper::Nohup => false,
    }
}

fn wrapper_long_takes_value(kind: CmdWrapper, long: &str) -> bool {
    match kind {
        CmdWrapper::Timeout => matches!(long, "signal" | "kill-after"),
        CmdWrapper::Nice => long == "adjustment",
        CmdWrapper::Nohup => false,
    }
}

fn wrapper_flag_skip(kind: CmdWrapper, arg: &str) -> Option<usize> {
    if arg == "-" {
        return Some(1);
    }
    if !arg.starts_with('-') {
        return None;
    }
    if let Some(long) = arg.strip_prefix("--") {
        if long.contains('=') {
            return Some(1);
        }
        return Some(if wrapper_long_takes_value(kind, long) {
            2
        } else {
            1
        });
    }
    let mut chars = arg[1..].chars();
    while let Some(c) = chars.next() {
        if wrapper_takes_value(kind, c) {
            return Some(if chars.next().is_some() { 1 } else { 2 });
        }
    }
    Some(1)
}

pub(crate) fn env_takes_value(flag: char) -> bool {
    matches!(flag, 'u' | 'C' | 'S' | 'P' | 'a' | 'f')
}

pub(crate) fn env_flag_skip(arg: &str) -> Option<usize> {
    if arg == "-" {
        return Some(1);
    }
    if !arg.starts_with('-') {
        return None;
    }
    if let Some(long) = arg.strip_prefix("--") {
        if long.contains('=') {
            return Some(1);
        }
        return Some(match long {
            "unset" | "split-string" | "chdir" | "argv0" | "file" => 2,
            _ => 1,
        });
    }
    let mut chars = arg[1..].chars();
    while let Some(c) = chars.next() {
        if env_takes_value(c) {
            return Some(if chars.next().is_some() { 1 } else { 2 });
        }
    }
    Some(1)
}

fn check_env_flag_dests(
    args: &[impl AsRef<str>],
    root: &Path,
    policy: &DenyPolicy,
) -> Result<(), CheckDestError> {
    check_env_flag_dests_inner(args, root, policy, false)
}

/// Dest-deny a `-S`/`--split-string` operand as a command string, then
/// re-walk leftover tokens as env flags (`--file=`, `-f`, `NAME=value`).
fn check_env_split_string_dests(
    operand: &str,
    root: &Path,
    policy: &DenyPolicy,
) -> Result<(), CheckDestError> {
    check_command_dests(operand, root, policy)?;
    let leftover: Vec<&str> = operand.split_whitespace().collect();
    check_env_flag_dests_inner(&leftover, root, policy, true)
}

fn check_env_flag_dests_inner(
    args: &[impl AsRef<str>],
    root: &Path,
    policy: &DenyPolicy,
    deny_assign_values: bool,
) -> Result<(), CheckDestError> {
    let mut i = 0;
    while i < args.len() {
        let raw = args[i].as_ref();
        if raw == "--" || raw == "-" {
            return continue_env_after_operand(&args[i + 1..], root, policy);
        }
        if !raw.starts_with('-') {
            if raw.contains('=') {
                if deny_assign_values
                    && let Some((_, value)) = raw.split_once('=')
                    && !value.is_empty()
                {
                    check_env_file_dest(value, root, policy)?;
                }
                i += 1;
                continue;
            }
            return continue_env_after_operand(&args[i..], root, policy);
        }
        if let Some(long) = raw.strip_prefix("--") {
            if let Some((name, value)) = long.split_once('=') {
                check_env_named_operand(name, value, root, policy)?;
                i += 1;
                continue;
            }
            let next = args.get(i + 1).map(|s| s.as_ref());
            match long {
                "split-string" | "file" | "unset" | "chdir" | "argv0" => {
                    if let Some(next) = next {
                        check_env_named_operand(long, next, root, policy)?;
                    }
                    i += 2;
                }
                _ => i += 1,
            }
            continue;
        }
        let mut chars = raw[1..].chars();
        let mut value_flag = None;
        let mut attached = String::new();
        while let Some(c) = chars.next() {
            if env_takes_value(c) {
                value_flag = Some(c);
                attached = chars.collect();
                break;
            }
        }
        match value_flag {
            Some(flag) => {
                let operand = if attached.is_empty() {
                    args.get(i + 1).map(|s| s.as_ref())
                } else {
                    Some(attached.as_str())
                };
                if let Some(operand) = operand {
                    match flag {
                        'S' => check_env_split_string_dests(operand, root, policy)?,
                        'f' => check_env_file_dest(operand, root, policy)?,
                        _ => {}
                    }
                }
                i += if attached.is_empty() { 2 } else { 1 };
            }
            None => i += 1,
        }
    }
    Ok(())
}

fn continue_env_after_operand(
    args: &[impl AsRef<str>],
    root: &Path,
    policy: &DenyPolicy,
) -> Result<(), CheckDestError> {
    let start = skip_all_wrappers(args);
    if args.get(start).is_some_and(|t| is_env_program(t.as_ref())) {
        return check_env_flag_dests(&args[start + 1..], root, policy);
    }
    Ok(())
}

fn check_env_named_operand(
    name: &str,
    value: &str,
    root: &Path,
    policy: &DenyPolicy,
) -> Result<(), CheckDestError> {
    match name {
        "split-string" => check_env_split_string_dests(value, root, policy),
        "file" => check_env_file_dest(value, root, policy),
        _ => Ok(()),
    }
}

fn check_env_file_dest(path: &str, root: &Path, policy: &DenyPolicy) -> Result<(), CheckDestError> {
    let dest = dest_under_root(root, path);
    check_dest(&dest.to_string_lossy(), policy, None).map(|_| ())
}

/// Join extracted command dests under `root` and dest-deny each.
///
/// Absolute dests stay as given. Empty and flag-looking peeled tokens
/// are skipped. After peeling, an `env`/`env.exe` token dest-denies
/// the following tokens with the same env-flag dest check used for
/// argv0 env. Does not peel `--flag=.env`.
pub fn check_command_dests(
    command: &str,
    root: &Path,
    policy: &DenyPolicy,
) -> Result<(), CheckDestError> {
    for (_display, candidate) in command_path_tokens(command) {
        for peeled in peel_shell_parts(&candidate) {
            if peeled.is_empty() || peeled.starts_with('-') {
                continue;
            }
            let dest = dest_under_root(root, peeled);
            check_dest(&dest.to_string_lossy(), policy, None)?;
        }
    }
    check_command_string_env_dests(command, root, policy)
}

/// After peeling a command string, dest-deny env `-S`/`--file` operands.
///
/// Recurses into a shell `-c` body. Also peels `cmd` / `pwsh` `/c`,
/// `-Command`, `-CommandWithArgs`, `-EncodedCommand`, `-EncodedArguments`,
/// and `-File` (including `--switch` and unique prefixes) from remaining
/// string tokens. Does not peel generic `--flag=.env`.
fn check_command_string_env_dests(
    command: &str,
    root: &Path,
    policy: &DenyPolicy,
) -> Result<(), CheckDestError> {
    for part in peel_shell_parts(command) {
        let tokens = command_string_tokens(part);
        for (i, token) in tokens.iter().enumerate() {
            if is_env_program(*token) {
                check_env_flag_dests(&tokens[i + 1..], root, policy)?;
            }
            if let Some(body) = shell_c_body(token, tokens.get(i + 1).copied()) {
                check_command_string_env_dests(body, root, policy)?;
            }
            if is_cmd_program(token) || is_powershell_program(token) {
                check_cmd_powershell_remaining_dests(token, &tokens[i + 1..], root, policy)?;
            }
        }
    }
    Ok(())
}

/// Whitespace words; matching quotes yield the inner string as one token.
fn command_string_tokens(command: &str) -> Vec<&str> {
    let bytes = command.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i] == b'\'' || bytes[i] == b'"' {
            let q = bytes[i];
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != q {
                i += 1;
            }
            out.push(&command[start..i]);
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        out.push(&command[start..i]);
    }
    out
}

/// Committed dotenv templates, not live env files.
pub fn is_env_template_basename(name: &str) -> bool {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    base.starts_with(".env.")
        && (base.ends_with(".example") || base.ends_with(".sample") || base.ends_with(".template"))
}

pub fn path_matches_deny_glob(pattern: &str, path: &str) -> bool {
    let pattern = normalize_glob_text(pattern);
    let path = normalize_glob_text(path);
    let pat: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match_glob_segments(&pat, &segs)
}

pub fn path_is_denied_glob(globs: &[String], path: &str) -> bool {
    first_matching_deny_glob(globs, path).is_some()
}

fn first_matching_deny_glob(globs: &[String], path: &str) -> Option<String> {
    let template = is_env_template_basename(path);
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    globs
        .iter()
        .find(|g| {
            if template && is_default_env_star_glob(g) {
                return false;
            }
            path_matches_deny_glob(g, path) || path_matches_deny_glob(g, base)
        })
        .cloned()
}

fn is_default_env_star_glob(pattern: &str) -> bool {
    normalize_glob_text(pattern) == "**/.env.*"
}

fn path_as_glob(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn normalize_glob_text(s: &str) -> String {
    s.replace('\\', "/").to_ascii_lowercase()
}

fn match_glob_segments(pat: &[&str], path: &[&str]) -> bool {
    match (pat.split_first(), path.split_first()) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some((&"**", rest)), _) => {
            if rest.is_empty() {
                return true;
            }
            for i in 0..=path.len() {
                if match_glob_segments(rest, &path[i..]) {
                    return true;
                }
            }
            false
        }
        (Some((p, prest)), Some((h, hrest))) => {
            glob_segment(p, h) && match_glob_segments(prest, hrest)
        }
        (Some(_), None) => false,
    }
}

fn glob_segment(pat: &str, text: &str) -> bool {
    match_star(pat.as_bytes(), text.as_bytes())
}

fn match_star(pat: &[u8], text: &[u8]) -> bool {
    match pat.split_first() {
        None => text.is_empty(),
        Some((&b'*', rest)) => {
            for i in 0..=text.len() {
                if match_star(rest, &text[i..]) {
                    return true;
                }
            }
            false
        }
        Some((p, prest)) => match text.split_first() {
            Some((t, trest)) if p == t => match_star(prest, trest),
            _ => false,
        },
    }
}

#[derive(Debug)]
enum HardlinkHit {
    Allowed,
    Denied { sibling: Option<String> },
}

fn hardlink_sibling_denied(path: &Path, canon: Option<&Path>, policy: &DenyPolicy) -> bool {
    matches!(
        hardlink_sibling_hit(path, canon, policy),
        HardlinkHit::Denied { .. }
    )
}

fn hardlink_sibling_hit(path: &Path, canon: Option<&Path>, policy: &DenyPolicy) -> HardlinkHit {
    #[cfg(unix)]
    {
        hardlink_sibling_hit_unix(path, canon, policy)
    }
    #[cfg(windows)]
    {
        hardlink_sibling_hit_windows(path, canon, policy)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, canon, policy);
        HardlinkHit::Allowed
    }
}

#[cfg(unix)]
fn hardlink_sibling_hit_unix(
    path: &Path,
    canon: Option<&Path>,
    policy: &DenyPolicy,
) -> HardlinkHit {
    use std::os::unix::fs::MetadataExt;

    let meta = match canon
        .map(std::fs::metadata)
        .unwrap_or_else(|| std::fs::symlink_metadata(path))
    {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return HardlinkHit::Denied { sibling: None };
        }
        Err(_) => return HardlinkHit::Allowed,
    };
    // Directory nlink counts children, not extra names for this inode.
    if meta.file_type().is_dir() {
        return HardlinkHit::Allowed;
    }
    let nlink = meta.nlink();
    if nlink <= 1 {
        return HardlinkHit::Allowed;
    }
    let mut parents = Vec::new();
    push_scan_parent(&mut parents, path.parent());
    if let Some(c) = canon {
        push_scan_parent(&mut parents, c.parent());
    }
    if parents.is_empty() {
        return HardlinkHit::Denied { sibling: None };
    }
    let mut found = 0u64;
    for parent in &parents {
        let entries = match std::fs::read_dir(parent) {
            Ok(rd) => rd,
            Err(_) => return HardlinkHit::Denied { sibling: None },
        };
        for entry in entries.flatten() {
            let entry_path = entry.path();
            let sibling_meta = match std::fs::symlink_metadata(&entry_path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if sibling_meta.dev() != meta.dev() || sibling_meta.ino() != meta.ino() {
                continue;
            }
            if path_is_denied_glob(policy.globs(), &path_as_glob(&entry_path)) {
                let sibling = entry_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned());
                return HardlinkHit::Denied { sibling };
            }
            found += 1;
        }
    }
    if found < nlink {
        HardlinkHit::Denied { sibling: None }
    } else {
        HardlinkHit::Allowed
    }
}

#[cfg(unix)]
fn push_scan_parent(parents: &mut Vec<PathBuf>, parent: Option<&Path>) {
    let parent = match parent {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        Some(_) => PathBuf::from("."),
        None => return,
    };
    let key = std::fs::canonicalize(&parent).unwrap_or(parent);
    if !parents.iter().any(|p| p == &key) {
        parents.push(key);
    }
}

/// Win32 `ERROR_NO_MORE_FILES` (FindNextFile).
#[cfg(any(windows, test))]
const WIN_ERROR_NO_MORE_FILES: u32 = 18;
/// Win32 `ERROR_HANDLE_EOF` (FindNextFileNameW).
#[cfg(any(windows, test))]
const WIN_ERROR_HANDLE_EOF: u32 = 38;

#[cfg(any(windows, test))]
fn win_find_next_exhausted(err: u32) -> bool {
    err == WIN_ERROR_NO_MORE_FILES || err == WIN_ERROR_HANDLE_EOF
}

/// Dest-deny from NTFS names plus `nNumberOfLinks`.
/// Incomplete listing (`names.len() < nlink`) is HardlinkSibling.
#[cfg(any(windows, test))]
fn hardlink_hit_from_win_names(
    names: &[std::ffi::OsString],
    nlink: u32,
    policy: &DenyPolicy,
) -> HardlinkHit {
    if names.len() < nlink as usize {
        return HardlinkHit::Denied { sibling: None };
    }
    if names.len() <= 1 {
        return HardlinkHit::Allowed;
    }
    for n in names {
        let s = n.to_string_lossy().replace('\\', "/");
        if path_is_denied_glob(policy.globs(), &s) {
            let sibling = Path::new(&s)
                .file_name()
                .map(|base| base.to_string_lossy().into_owned());
            return HardlinkHit::Denied { sibling };
        }
    }
    HardlinkHit::Allowed
}

/// `MetadataExt::file_index` is unstable (`windows_by_handle`). List names
/// with FindFirstFileNameW instead.
#[cfg(windows)]
fn hardlink_sibling_hit_windows(
    path: &Path,
    canon: Option<&Path>,
    policy: &DenyPolicy,
) -> HardlinkHit {
    let probe = canon.unwrap_or(path);
    let meta = match std::fs::metadata(probe) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return HardlinkHit::Denied { sibling: None };
        }
        Err(_) => return HardlinkHit::Allowed,
    };
    if meta.is_dir() {
        return HardlinkHit::Allowed;
    }
    let nlink = match win_path_by_handle(probe) {
        Ok(info) => info.nlink,
        Err(_) => return HardlinkHit::Denied { sibling: None },
    };
    match win_hardlink_names(probe) {
        Ok(names) => hardlink_hit_from_win_names(&names, nlink, policy),
        Err(_) => HardlinkHit::Denied { sibling: None },
    }
}

#[cfg(windows)]
fn win_hardlink_names(path: &Path) -> std::io::Result<Vec<std::ffi::OsString>> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    type Handle = *mut core::ffi::c_void;
    type Dword = u32;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    const ERROR_MORE_DATA: Dword = 234;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn FindFirstFileNameW(
            lp_file_name: *const u16,
            dw_flags: Dword,
            string_length: *mut Dword,
            link_name: *mut u16,
        ) -> Handle;
        fn FindNextFileNameW(
            h_find_stream: Handle,
            string_length: *mut Dword,
            link_name: *mut u16,
        ) -> i32;
        fn FindClose(h_find_file: Handle) -> i32;
        fn GetLastError() -> Dword;
    }

    struct FindNameHandle(Handle);
    impl Drop for FindNameHandle {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: `self.0` came from FindFirstFileNameW.
                unsafe {
                    FindClose(self.0);
                }
                self.0 = INVALID_HANDLE_VALUE;
            }
        }
    }

    fn wide_to_os(buf: &[u16], claimed: usize) -> std::ffi::OsString {
        let end = buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(claimed.min(buf.len()));
        std::ffi::OsString::from_wide(&buf[..end])
    }

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut len: Dword = 256;
    let mut buf = vec![0u16; 256];
    let handle = loop {
        // SAFETY: `wide` is a NUL-terminated path; `buf` is at least `len` units.
        let h = unsafe { FindFirstFileNameW(wide.as_ptr(), 0, &mut len, buf.as_mut_ptr()) };
        if h != INVALID_HANDLE_VALUE {
            break FindNameHandle(h);
        }
        let err = unsafe { GetLastError() };
        if err == ERROR_MORE_DATA {
            buf.resize(len as usize, 0);
            continue;
        }
        return Err(std::io::Error::from_raw_os_error(err as i32));
    };

    let mut names = vec![wide_to_os(&buf, len as usize)];
    loop {
        len = buf.len() as Dword;
        // SAFETY: `handle.0` came from FindFirstFileNameW; `buf` matches `len`.
        let ok = unsafe { FindNextFileNameW(handle.0, &mut len, buf.as_mut_ptr()) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_MORE_DATA {
                buf.resize(len as usize, 0);
                continue;
            }
            if win_find_next_exhausted(err) {
                break;
            }
            return Err(std::io::Error::from_raw_os_error(err as i32));
        }
        names.push(wide_to_os(&buf, len as usize));
    }
    Ok(names)
}

#[cfg(windows)]
struct WinHandleInfo {
    volume: u32,
    index: u64,
    nlink: u32,
}

#[cfg(windows)]
fn win_path_by_handle(path: &Path) -> std::io::Result<WinHandleInfo> {
    use std::os::windows::ffi::OsStrExt;

    type Handle = *mut core::ffi::c_void;
    type Dword = u32;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    const FILE_READ_ATTRIBUTES: Dword = 0x0080;
    const FILE_SHARE_READ: Dword = 0x0001;
    const FILE_SHARE_WRITE: Dword = 0x0002;
    const FILE_SHARE_DELETE: Dword = 0x0004;
    const OPEN_EXISTING: Dword = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: Dword = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: Dword = 0x0020_0000;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: Dword,
            dw_share_mode: Dword,
            lp_security_attributes: *mut core::ffi::c_void,
            dw_creation_disposition: Dword,
            dw_flags_and_attributes: Dword,
            h_template_file: Handle,
        ) -> Handle;
        fn CloseHandle(h_object: Handle) -> i32;
        fn GetLastError() -> Dword;
    }

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is a NUL-terminated path.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            core::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            core::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        return Err(std::io::Error::from_raw_os_error(err as i32));
    }
    let info = win_handle_info(handle);
    unsafe {
        CloseHandle(handle);
    }
    info
}

#[cfg(windows)]
fn win_handle_info(handle: *mut core::ffi::c_void) -> std::io::Result<WinHandleInfo> {
    type Dword = u32;

    #[repr(C)]
    struct ByHandleFileInformation {
        dw_file_attributes: Dword,
        ft_creation_time_lo: Dword,
        ft_creation_time_hi: Dword,
        ft_last_access_time_lo: Dword,
        ft_last_access_time_hi: Dword,
        ft_last_write_time_lo: Dword,
        ft_last_write_time_hi: Dword,
        dw_volume_serial_number: Dword,
        n_file_size_high: Dword,
        n_file_size_low: Dword,
        n_number_of_links: Dword,
        n_file_index_high: Dword,
        n_file_index_low: Dword,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(
            h_file: *mut core::ffi::c_void,
            lp_file_information: *mut ByHandleFileInformation,
        ) -> i32;
        fn GetLastError() -> Dword;
    }

    let mut info = ByHandleFileInformation {
        dw_file_attributes: 0,
        ft_creation_time_lo: 0,
        ft_creation_time_hi: 0,
        ft_last_access_time_lo: 0,
        ft_last_access_time_hi: 0,
        ft_last_write_time_lo: 0,
        ft_last_write_time_hi: 0,
        dw_volume_serial_number: 0,
        n_file_size_high: 0,
        n_file_size_low: 0,
        n_number_of_links: 0,
        n_file_index_high: 0,
        n_file_index_low: 0,
    };
    // SAFETY: `handle` is an open file handle; `info` is the Win32 layout.
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(std::io::Error::from_raw_os_error(err as i32));
    }
    Ok(WinHandleInfo {
        volume: info.dw_volume_serial_number,
        index: (u64::from(info.n_file_index_high) << 32) | u64::from(info.n_file_index_low),
        nlink: info.n_number_of_links,
    })
}

fn peel_shell_meta(s: &str) -> &str {
    s.trim_matches(|c: char| matches!(c, ';' | '|' | '&' | ')' | '(' | '<' | '>' | '`' | ','))
}

fn peel_shell_parts(s: &str) -> impl Iterator<Item = &str> {
    s.split([';', '|', '&', ')', '(', '<', '>', '`', ','])
        .map(peel_shell_meta)
        .filter(|p| !p.is_empty())
}

fn candidate_is_denied(candidate: &str, policy: &DenyPolicy) -> bool {
    for peeled in peel_shell_parts(candidate) {
        if peeled.starts_with('-') {
            continue;
        }
        if is_path_denied(Path::new(peeled), policy) {
            return true;
        }
        if let Some((_, after)) = peeled.rsplit_once(':') {
            let after = peel_shell_meta(after);
            if !after.is_empty()
                && !after.starts_with('-')
                && is_path_denied(Path::new(after), policy)
            {
                return true;
            }
        }
    }
    false
}

fn command_path_tokens(command: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    collect_function_calls(command, &mut out);
    collect_quoted_and_words(command, &mut out);
    out
}

fn collect_function_calls(s: &str, out: &mut Vec<(String, String)>) {
    let mut pos = 0;
    while let Some((end, display, path)) = next_function_call(s, pos) {
        out.push((display, path));
        pos = end;
    }
}

fn next_function_call(s: &str, from: usize) -> Option<(usize, String, String)> {
    let bytes = s.as_bytes();
    let mut i = from;
    while i < bytes.len() {
        if is_ident_start(bytes[i]) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_ident_cont(bytes[i]) {
                i += 1;
            }
            let ident_end = i;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'(' {
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                if i < bytes.len() && (bytes[i] == b'\'' || bytes[i] == b'"') {
                    let q = bytes[i];
                    i += 1;
                    let path_start = i;
                    while i < bytes.len() && bytes[i] != q {
                        i += 1;
                    }
                    if i < bytes.len() && bytes[i] == q {
                        let path = s[path_start..i].to_string();
                        i += 1;
                        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                            i += 1;
                        }
                        if i < bytes.len() && bytes[i] == b')' {
                            i += 1;
                            let display = s[start..i].to_string();
                            return Some((i, display, path));
                        }
                    }
                }
            }
            i = ident_end.max(start + 1);
            continue;
        }
        i += 1;
    }
    None
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_ident_cont(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn collect_quoted_and_words(s: &str, out: &mut Vec<(String, String)>) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i] == b'\'' || bytes[i] == b'"' {
            let q = bytes[i];
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != q {
                i += 1;
            }
            let inner = &s[start..i];
            if i < bytes.len() {
                i += 1;
            }
            collect_function_calls(inner, out);
            collect_quoted_and_words(inner, out);
            out.push((inner.to_string(), inner.to_string()));
            continue;
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let raw = &s[start..i];
        let peeled = peel_shell_meta(raw);
        out.push((raw.to_string(), peeled.to_string()));
        if let Some((_, after)) = peeled.rsplit_once(':') {
            out.push((raw.to_string(), after.to_string()));
        }
    }
}

/// v1 list is byte-identical to Bline `default_secret_denies()`.
/// Do not add `**/.azure/**` or `**/.config/gh/**`.
pub fn default_secret_denies() -> Vec<String> {
    vec![
        "**/.env".into(),
        "**/.env.*".into(),
        "**/*.pem".into(),
        "**/*.key".into(),
        "**/*.p12".into(),
        "**/*.pfx".into(),
        "**/id_rsa".into(),
        "**/id_ed25519".into(),
        "**/id_ecdsa".into(),
        "**/id_dsa".into(),
        "**/id_eddsa".into(),
        "**/.npmrc".into(),
        "**/.pypirc".into(),
        "**/.docker/config.json".into(),
        "**/kubeconfig".into(),
        "**/.kube/config".into(),
        "**/secrets.json".into(),
        "**/service-account*.json".into(),
        "**/.ssh/**".into(),
        "**/token.json".into(),
        "**/secring.gpg".into(),
        "**/.gnupg/private-keys-v1.d/**".into(),
        "**/credentials.json".into(),
        "**/.aws/credentials".into(),
        "**/.netrc".into(),
        "**/secrets/**".into(),
        "**/credentials/**".into(),
        "**/gateway/pairing.json".into(),
        "**/auth.json".into(),
        "**/auth-*.json".into(),
    ]
}

#[cfg(test)]
mod classify_hardlink_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn hardlink_denied_when_canon_is_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let env = dir.path().join(".env");
        std::fs::write(&env, "API_KEY=secret\n").expect("write .env");
        let sibling = dir.path().join("notes.txt");
        std::fs::hard_link(&env, &sibling).expect("hardlink");
        let policy = DenyPolicy::default();
        assert!(
            hardlink_sibling_denied(&sibling, None, &policy),
            "nlink > 1 must dest-deny when canonicalize is unavailable"
        );
        assert!(!hardlink_sibling_denied(
            Path::new("no-such-workpen-hardlink-xyz"),
            None,
            &policy
        ));
    }

    #[test]
    fn win_find_next_exhausted_is_eof_not_other_errors() {
        assert!(win_find_next_exhausted(WIN_ERROR_NO_MORE_FILES));
        assert!(win_find_next_exhausted(WIN_ERROR_HANDLE_EOF));
        assert!(!win_find_next_exhausted(5));
        assert!(!win_find_next_exhausted(234));
    }

    #[test]
    fn win_names_shorter_than_nlink_is_hardlink_sibling() {
        let policy = DenyPolicy::default();
        let names = [std::ffi::OsString::from(r"C:\ws\notes.txt")];
        match hardlink_hit_from_win_names(&names, 2, &policy) {
            HardlinkHit::Denied { sibling: None } => {}
            other => panic!("incomplete name list must deny, got {other:?}"),
        }
    }

    #[test]
    fn win_names_matching_nlink_without_deny_glob_is_allowed() {
        let policy = DenyPolicy::default();
        let names = [std::ffi::OsString::from(r"C:\ws\notes.txt")];
        match hardlink_hit_from_win_names(&names, 1, &policy) {
            HardlinkHit::Allowed => {}
            other => panic!("single name and nlink 1 must allow, got {other:?}"),
        }
        let two = [
            std::ffi::OsString::from(r"C:\ws\a.txt"),
            std::ffi::OsString::from(r"C:\ws\b.txt"),
        ];
        match hardlink_hit_from_win_names(&two, 2, &policy) {
            HardlinkHit::Allowed => {}
            other => panic!("listed names with no deny glob must allow, got {other:?}"),
        }
    }

    #[test]
    fn win_names_denied_glob_reports_sibling_basename() {
        let policy = DenyPolicy::default();
        let names = [
            std::ffi::OsString::from(r"C:\ws\.env"),
            std::ffi::OsString::from(r"C:\ws\notes.txt"),
        ];
        match hardlink_hit_from_win_names(&names, 2, &policy) {
            HardlinkHit::Denied {
                sibling: Some(name),
            } => assert_eq!(name, ".env"),
            other => panic!("hardlink of .env must name sibling, got {other:?}"),
        }
    }
}
