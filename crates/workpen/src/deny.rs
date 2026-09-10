//! Dest-deny predicate. Glob match, hardlink sibling, patch dests, argv tokens.

use std::path::{Path, PathBuf};

/// Portable dest-deny policy. Same globs on every OS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyPolicy {
    globs: Vec<String>,
}

impl Default for DenyPolicy {
    fn default() -> Self {
        Self {
            globs: default_secret_denies(),
        }
    }
}

impl DenyPolicy {
    pub fn new(globs: Vec<String>) -> Self {
        Self { globs }
    }

    /// `default_secret_denies()` plus extras. Extras never replace defaults.
    pub fn with_extra(extra: impl IntoIterator<Item = String>) -> Self {
        let mut globs = default_secret_denies();
        for g in extra {
            if !globs.iter().any(|x| x == &g) {
                globs.push(g);
            }
        }
        Self { globs }
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

    let canon = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(_) => return None,
    };
    if path_is_denied_glob(policy.globs(), &path_as_glob(&canon)) {
        return Some(DestDenyKind::DenyGlob);
    }
    if hardlink_sibling_denied(&canon, policy) {
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
    if is_env_template_basename(path) {
        return false;
    }
    globs.iter().any(|g| path_matches_deny_glob(g, path))
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

fn hardlink_sibling_denied(canon: &Path, policy: &DenyPolicy) -> bool {
    #[cfg(unix)]
    {
        hardlink_sibling_denied_unix(canon, policy)
    }
    #[cfg(windows)]
    {
        hardlink_sibling_denied_windows(canon, policy)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (canon, policy);
        false
    }
}

#[cfg(unix)]
fn hardlink_sibling_denied_unix(canon: &Path, policy: &DenyPolicy) -> bool {
    use std::os::unix::fs::MetadataExt;

    let meta = match std::fs::metadata(canon) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let nlink = meta.nlink();
    if nlink <= 1 {
        return false;
    }
    let parent = match canon.parent() {
        Some(p) => p,
        None => return true,
    };
    let entries = match std::fs::read_dir(parent) {
        Ok(rd) => rd,
        Err(_) => return true,
    };
    let mut same = 0u64;
    for entry in entries.flatten() {
        let path = entry.path();
        let sibling_meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if sibling_meta.dev() != meta.dev() || sibling_meta.ino() != meta.ino() {
            continue;
        }
        same += 1;
        if path_is_denied_glob(policy.globs(), &path_as_glob(&path)) {
            return true;
        }
    }
    same < nlink
}

/// `MetadataExt::file_index` is unstable (`windows_by_handle`). List names
/// with FindFirstFileNameW instead.
#[cfg(windows)]
fn hardlink_sibling_denied_windows(canon: &Path, policy: &DenyPolicy) -> bool {
    match win_hardlink_names(canon) {
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

fn peel_shell_meta(s: &str) -> &str {
    s.trim_matches(|c: char| matches!(c, ';' | '|' | '&' | ')' | '(' | '<' | '>' | '`' | ','))
}

fn candidate_is_denied(candidate: &str, policy: &DenyPolicy) -> bool {
    let peeled = peel_shell_meta(candidate);
    if peeled.is_empty() || peeled.starts_with('-') {
        return false;
    }
    if path_is_denied_glob(policy.globs(), peeled) {
        return true;
    }
    if let Some((_, after)) = peeled.rsplit_once(':') {
        let after = peel_shell_meta(after);
        if !after.is_empty()
            && !after.starts_with('-')
            && path_is_denied_glob(policy.globs(), after)
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
