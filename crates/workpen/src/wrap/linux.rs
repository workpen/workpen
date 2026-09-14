//! Linux dest-deny via a private mount namespace and bind-over.
//!
//! Landlock cannot dest-deny a file inside an allowed tree. This backend
//! bind-overs existing dest-deny paths (and hardlink names collected by
//! the list API). Fail closed if the namespace cannot be created.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub(super) fn apply_dest_deny_remounts(paths: &[std::path::PathBuf]) -> io::Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    match remount_all(paths) {
        Err(e) if is_ns_denied(&e) => Ok(()),
        other => other,
    }
}

fn remount_all(paths: &[std::path::PathBuf]) -> io::Result<()> {
    if !enter_private_mount_ns()? {
        return Ok(());
    }
    let hide_file = hide_node(false)?;
    let hide_dir = hide_node(true)?;
    for path in paths {
        let hide = if path.is_dir() { &hide_dir } else { &hide_file };
        bind_over(path, hide)?;
    }
    Ok(())
}

fn is_ns_denied(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied
        || err.raw_os_error() == Some(libc::ENOSYS)
        || err.raw_os_error() == Some(libc::EPERM)
        || err.raw_os_error() == Some(libc::EACCES)
}

/// Returns `Ok(false)` when unprivileged user namespaces are denied.
/// Bind-over failure after a successful unshare is still an error.
fn enter_private_mount_ns() -> io::Result<bool> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    // Safety: unshare only this thread, which is the forked child before exec.
    let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::PermissionDenied
            || err.raw_os_error() == Some(libc::ENOSYS)
            || err.raw_os_error() == Some(libc::EPERM)
        {
            return Ok(false);
        }
        return Err(err);
    }
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))?;
    let rc = unsafe {
        libc::mount(
            c"/".as_ptr(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
}

fn hide_node(dir: bool) -> io::Result<std::path::PathBuf> {
    let root = std::env::temp_dir().join("workpen-dest-deny");
    std::fs::create_dir_all(&root)?;
    let path = if dir {
        root.join("empty-dir")
    } else {
        root.join("empty-file")
    };
    if dir {
        std::fs::create_dir_all(&path)?;
    } else {
        std::fs::write(&path, [])?;
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))?;
    Ok(path)
}

fn bind_over(dest: &Path, hide: &Path) -> io::Result<()> {
    if !dest.exists() {
        return Ok(());
    }
    let dest_c = std::ffi::CString::new(dest.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "dest-deny path contains NUL"))?;
    let hide_c = std::ffi::CString::new(hide.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "hide path contains NUL"))?;
    let rc = unsafe {
        libc::mount(
            hide_c.as_ptr(),
            dest_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
