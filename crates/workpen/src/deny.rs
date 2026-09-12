//! Dest-deny predicate. Glob match, hardlink sibling, patch dests, argv tokens.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
}

impl DestDeny {
    /// Wording distinguishes glob vs hardlink.
    /// Hardlink must not say "matches deny glob".
    pub fn message(&self) -> String {
        match self.kind {
            DestDenyKind::DenyGlob => format!(
                "path denied by sandbox profile (matches deny glob): {}",
                self.display
            ),
            DestDenyKind::HardlinkSibling => format!(
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
    if path_is_denied_glob(policy.globs(), &path_as_glob(path)) {
        return Some(DestDenyKind::DenyGlob);
    }

    let canon = std::fs::canonicalize(path).ok();
    if let Some(canon) = &canon
        && path_is_denied_glob(policy.globs(), &path_as_glob(canon))
    {
        return Some(DestDenyKind::DenyGlob);
    }
    if hardlink_sibling_denied(path, canon.as_deref(), policy) {
        return Some(DestDenyKind::HardlinkSibling);
    }
    None
}

pub fn is_path_denied(path: &Path, policy: &DenyPolicy) -> bool {
    classify_dest(path, policy).is_some()
}

pub fn dest_deny_message(path: &Path, display: &str, policy: &DenyPolicy) -> Option<String> {
    classify_dest(path, policy).map(|kind| {
        DestDeny {
            kind,
            path: path.to_path_buf(),
            display: display.to_owned(),
        }
        .message()
    })
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
    if let Some(kind) = classify_dest(raw, policy) {
        return Err(CheckDestError::DestDeny(DestDenyError::Denied(DestDeny {
            kind,
            path: raw.to_path_buf(),
            display: path.to_owned(),
        })));
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

    if let Some(kind) = classify_dest(&resolved, policy) {
        return Err(CheckDestError::DestDeny(DestDenyError::Denied(DestDeny {
            kind,
            path: resolved,
            display: path.to_owned(),
        })));
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
        if let Some(kind) = classify_dest(dest, policy) {
            return Err(DestDenyError::Denied(DestDeny {
                kind,
                path: dest.to_path_buf(),
                display: dest.display().to_string(),
            }));
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
        if let Some(kind) = classify_dest(dest, policy) {
            return Err(DestDenyError::Denied(DestDeny {
                kind,
                path: dest.to_path_buf(),
                display: (*display).to_owned(),
            }));
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

/// Join extracted command dests under `root` and dest-deny each.
///
/// Absolute dests stay as given. Empty and flag-looking peeled tokens
/// are skipped. Does not peel `--flag=.env`.
pub fn check_command_dests(
    command: &str,
    root: &Path,
    policy: &DenyPolicy,
) -> Result<(), CheckDestError> {
    for (_display, candidate) in command_path_tokens(command) {
        let peeled = peel_shell_meta(&candidate);
        if peeled.is_empty() || peeled.starts_with('-') {
            continue;
        }
        let dest = if Path::new(peeled).is_absolute() {
            PathBuf::from(peeled)
        } else {
            root.join(peeled)
        };
        check_dest(&dest.to_string_lossy(), policy, None)?;
    }
    Ok(())
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
    let template = is_env_template_basename(path);
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    globs.iter().any(|g| {
        if template && is_default_env_star_glob(g) {
            return false;
        }
        path_matches_deny_glob(g, path) || path_matches_deny_glob(g, base)
    })
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

fn hardlink_sibling_denied(path: &Path, canon: Option<&Path>, policy: &DenyPolicy) -> bool {
    #[cfg(unix)]
    {
        hardlink_sibling_denied_unix(path, canon, policy)
    }
    #[cfg(windows)]
    {
        hardlink_sibling_denied_windows(path, canon, policy)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, canon, policy);
        false
    }
}

#[cfg(unix)]
fn hardlink_sibling_denied_unix(path: &Path, canon: Option<&Path>, policy: &DenyPolicy) -> bool {
    use std::os::unix::fs::MetadataExt;

    let meta = match canon
        .map(std::fs::metadata)
        .unwrap_or_else(|| std::fs::symlink_metadata(path))
    {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return true,
        Err(_) => return false,
    };
    // Directory nlink counts children, not extra names for this inode.
    if meta.file_type().is_dir() {
        return false;
    }
    let nlink = meta.nlink();
    if nlink <= 1 {
        return false;
    }
    let mut parents = Vec::new();
    push_scan_parent(&mut parents, path.parent());
    if let Some(c) = canon {
        push_scan_parent(&mut parents, c.parent());
    }
    if parents.is_empty() {
        return true;
    }
    let mut found = 0u64;
    for parent in &parents {
        let entries = match std::fs::read_dir(parent) {
            Ok(rd) => rd,
            Err(_) => return true,
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
                return true;
            }
            found += 1;
        }
    }
    found < nlink
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

/// `MetadataExt::file_index` is unstable (`windows_by_handle`). List names
/// with FindFirstFileNameW instead.
#[cfg(windows)]
fn hardlink_sibling_denied_windows(path: &Path, canon: Option<&Path>, policy: &DenyPolicy) -> bool {
    let probe = canon.unwrap_or(path);
    let meta = match std::fs::metadata(probe) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return true,
        Err(_) => return false,
    };
    if meta.is_dir() {
        return false;
    }
    match win_hardlink_names(probe) {
        Ok(names) if names.len() <= 1 => false,
        Ok(names) => names.iter().any(|n| {
            let s = n.to_string_lossy().replace('\\', "/");
            path_is_denied_glob(policy.globs(), &s)
        }),
        Err(_) => true,
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
            break h;
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
        // SAFETY: `handle` came from FindFirstFileNameW; `buf` matches `len`.
        let ok = unsafe { FindNextFileNameW(handle, &mut len, buf.as_mut_ptr()) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_MORE_DATA {
                buf.resize(len as usize, 0);
                continue;
            }
            break;
        }
        names.push(wide_to_os(&buf, len as usize));
    }
    // SAFETY: `handle` is an open FindFirst handle.
    unsafe {
        FindClose(handle);
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

fn candidate_is_denied(candidate: &str, policy: &DenyPolicy) -> bool {
    let peeled = peel_shell_meta(candidate);
    if peeled.is_empty() || peeled.starts_with('-') {
        return false;
    }
    if is_path_denied(Path::new(peeled), policy) {
        return true;
    }
    if let Some((_, after)) = peeled.rsplit_once(':') {
        let after = peel_shell_meta(after);
        if !after.is_empty() && !after.starts_with('-') && is_path_denied(Path::new(after), policy)
        {
            return true;
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
}
