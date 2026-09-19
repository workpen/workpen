//! Linux dest-deny via a private mount namespace and bind-over.
//!
//! Landlock cannot dest-deny a file inside an allowed tree. This backend
//! bind-overs existing dest-deny paths (and hardlink names collected by
//! the list API). If unshare is denied, remount is skipped. Hide or
//! bind-over errors after a successful unshare fail closed.

use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static TEST_ENTER: Cell<Option<bool>> = const { Cell::new(None) };
    static TEST_HIDE_FAIL: Cell<bool> = const { Cell::new(false) };
    static TEST_BIND_FAIL: Cell<bool> = const { Cell::new(false) };
}

fn is_ns_unavailable(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied
        || err.raw_os_error() == Some(libc::ENOSYS)
        || err.raw_os_error() == Some(libc::EPERM)
        || err.raw_os_error() == Some(libc::EACCES)
        // ubuntu-latest unshare/MS_PRIVATE remount of / can return EINVAL
        // (os error 22) when the runner cannot enter a private mount ns.
        || err.raw_os_error() == Some(libc::EINVAL)
}

/// Parent-side remount probe. Extra-root dests fail-closed when remount
/// is unavailable. Workspace dests become [`super::KernelApply::RemountSkipped`].
pub(super) fn remount_status(
    paths: &[PathBuf],
    workspace: &Path,
) -> Result<super::KernelApply, super::KernelError> {
    if paths.is_empty() {
        return Ok(super::KernelApply::Applied);
    }
    if remount_available() {
        return Ok(super::KernelApply::Applied);
    }
    if paths.iter().any(|p| !p.starts_with(workspace)) {
        return Err(super::KernelError::Apply(
            "extra-root dest-deny remount unavailable; child was not started".into(),
        ));
    }
    Ok(super::KernelApply::RemountSkipped)
}

fn remount_available() -> bool {
    #[cfg(test)]
    if let Some(entered) = TEST_ENTER.with(Cell::get) {
        return entered;
    }
    probe_private_mount_ns()
}

/// Fork, try enter, exit. Does not change the parent namespace.
fn probe_private_mount_ns() -> bool {
    // SAFETY: child only tries enter then `_exit`; parent waitpid reaps it.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        let ok = enter_private_mount_ns().unwrap_or(false);
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    let mut status = 0;
    // SAFETY: pid is the child we just forked.
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

pub(super) fn apply_dest_deny_remounts(paths: &[PathBuf], workspace: &Path) -> io::Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let expanded: Vec<PathBuf> = paths
        .iter()
        .flat_map(|p| super::dest_deny_rule_paths(p))
        .collect();
    // Create hide nodes before unshare so a planted shared temp path
    // cannot make hide_node fail after the namespace exists.
    let root = unique_hide_root()?;
    let hide_file = hide_node(&root, false)?;
    let hide_dir = hide_node(&root, true)?;
    remount_all(&expanded, workspace, &hide_file, &hide_dir)
}

fn remount_all(
    paths: &[PathBuf],
    workspace: &Path,
    hide_file: &Path,
    hide_dir: &Path,
) -> io::Result<()> {
    if !enter_private_mount_ns()? {
        if paths.iter().any(|p| !p.starts_with(workspace)) {
            return Err(io::Error::other(
                "extra-root dest-deny remount unavailable; child was not started",
            ));
        }
        return Ok(());
    }
    lock_namespaces()?;
    for path in paths {
        let hide = if path.is_dir() { hide_dir } else { hide_file };
        bind_over(path, hide)?;
    }
    Ok(())
}

/// After a successful remount enter, block nested userns/mount ns.
/// Fail-closed if the filter cannot be installed.
fn lock_namespaces() -> io::Result<()> {
    // BPF: load syscall nr; unshare/setns -> EPERM; clone3 -> ENOSYS; else allow.
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_SET_MODE_FILTER: u32 = 1;
    const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1;
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

    let unshare = libc::SYS_unshare as u32;
    let setns = libc::SYS_setns as u32;
    let clone3 = libc::SYS_clone3 as u32;
    let eperm = libc::EPERM as u32;
    let enosys = libc::ENOSYS as u32;

    let filter = [
        libc::sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: unshare,
        },
        libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | eperm,
        },
        libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: setns,
        },
        libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | eperm,
        },
        libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: clone3,
        },
        libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | enosys,
        },
        libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ];
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: child thread after fork; no_new_privs then TSYNC filter.
    let nnp = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if nnp != 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &prog as *const libc::sock_fprog,
        )
    };
    if rc != 0 {
        return Err(io::Error::other(format!(
            "namespace lockdown seccomp failed ({})",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Returns `Ok(false)` when the private mount ns cannot be created.
/// Hide or bind-over failure after a successful enter is still an error.
fn enter_private_mount_ns() -> io::Result<bool> {
    #[cfg(test)]
    if let Some(entered) = TEST_ENTER.with(Cell::get) {
        return Ok(entered);
    }
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    // Safety: unshare only this thread, which is the forked child before exec.
    let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if is_ns_unavailable(&err) {
            return Ok(false);
        }
        return Err(err);
    }
    if let Err(err) = write_id_maps(uid, gid) {
        if is_ns_unavailable(&err) {
            return Ok(false);
        }
        return Err(err);
    }
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
        let err = io::Error::last_os_error();
        if is_ns_unavailable(&err) {
            return Ok(false);
        }
        return Err(err);
    }
    Ok(true)
}

fn write_id_maps(uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))?;
    Ok(())
}

/// Unique directory this process owns. A planted
/// `temp_dir()/workpen-dest-deny/empty-file` cannot collide.
fn unique_hide_root() -> io::Result<PathBuf> {
    let mut template = std::env::temp_dir();
    template.push("workpen-dest-deny-XXXXXX");
    let mut buf = template.into_os_string().into_vec();
    buf.push(0);
    // Safety: `buf` is a NUL-terminated mkdtemp template; the pointer is
    // valid for the call and we rebuild the path from the same bytes.
    let ptr = unsafe { libc::mkdtemp(buf.as_mut_ptr().cast()) };
    if ptr.is_null() {
        return Err(io::Error::last_os_error());
    }
    buf.pop();
    Ok(PathBuf::from(std::ffi::OsString::from_vec(buf)))
}

fn hide_node(root: &Path, dir: bool) -> io::Result<PathBuf> {
    #[cfg(test)]
    if TEST_HIDE_FAIL.with(Cell::get) {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
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
    #[cfg(test)]
    if TEST_BIND_FAIL.with(Cell::get) {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
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
        let err = io::Error::last_os_error();
        return Err(io::Error::other(format!(
            "dest-deny remount unavailable; child was not started ({err})"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        TEST_BIND_FAIL, TEST_ENTER, TEST_HIDE_FAIL, apply_dest_deny_remounts, remount_status,
    };
    use std::path::{Path, PathBuf};

    struct Override {
        reset_hide: bool,
        reset_bind: bool,
    }

    impl Override {
        fn enter(entered: bool) -> Self {
            TEST_ENTER.with(|c| c.set(Some(entered)));
            Self {
                reset_hide: false,
                reset_bind: false,
            }
        }

        fn hide_fail() -> Self {
            TEST_HIDE_FAIL.with(|c| c.set(true));
            Self {
                reset_hide: true,
                reset_bind: false,
            }
        }

        fn bind_fail_after_enter() -> Self {
            TEST_ENTER.with(|c| c.set(Some(true)));
            TEST_BIND_FAIL.with(|c| c.set(true));
            Self {
                reset_hide: false,
                reset_bind: true,
            }
        }
    }

    impl Drop for Override {
        fn drop(&mut self) {
            TEST_ENTER.with(|c| c.set(None));
            if self.reset_hide {
                TEST_HIDE_FAIL.with(|c| c.set(false));
            }
            if self.reset_bind {
                TEST_BIND_FAIL.with(|c| c.set(false));
            }
        }
    }

    #[test]
    fn unshare_denied_skips_remount() {
        let _guard = Override::enter(false);
        let dest = PathBuf::from("/tmp/workpen-dest-deny-unshare-skip.env");
        apply_dest_deny_remounts(&[dest], Path::new("/tmp"))
            .expect("unshare denied must stay Ok (issue #92 remount skip)");
    }

    #[test]
    fn remount_status_is_skipped_when_dests_exist_and_enter_fails() {
        let _guard = Override::enter(false);
        let dest = PathBuf::from("/ws/.env");
        let got = remount_status(&[dest], Path::new("/ws")).expect("workspace skip");
        assert_eq!(got, crate::KernelApply::RemountSkipped);
    }

    #[test]
    fn remount_status_fails_closed_on_extra_root_when_enter_fails() {
        let _guard = Override::enter(false);
        let dest = PathBuf::from("/tmp/.env");
        remount_status(&[dest], Path::new("/ws")).expect_err("extra-root skip is Apply");
    }

    #[test]
    fn remount_status_applied_when_no_dests() {
        let _guard = Override::enter(false);
        let got = remount_status(&[], Path::new("/ws")).expect("empty dests");
        assert_eq!(got, crate::KernelApply::Applied);
    }

    #[test]
    fn hide_failure_is_error() {
        let _guard = Override::hide_fail();
        let dest = PathBuf::from("/tmp/workpen-dest-deny-hide-fail.env");
        let err = apply_dest_deny_remounts(&[dest], Path::new("/tmp"))
            .expect_err("hide_node EACCES must propagate");
        assert_eq!(err.raw_os_error(), Some(libc::EACCES));
    }

    #[test]
    fn bind_failure_after_enter_is_error() {
        let _guard = Override::bind_fail_after_enter();
        let dest = PathBuf::from("/tmp/workpen-dest-deny-bind-fail.env");
        let err = apply_dest_deny_remounts(&[dest], Path::new("/tmp"))
            .expect_err("bind_over EPERM after enter must propagate");
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn unshare_denied_extra_root_dest_is_error() {
        let _guard = Override::enter(false);
        let dest = PathBuf::from("/tmp/workpen-dest-deny-extra.env");
        apply_dest_deny_remounts(&[dest], Path::new("/workspace"))
            .expect_err("extra-root dest-deny without remount must fail closed");
    }

    #[test]
    fn einval_from_enter_is_ns_unavailable() {
        let err = std::io::Error::from_raw_os_error(libc::EINVAL);
        assert!(
            super::is_ns_unavailable(&err),
            "unshare/mount EINVAL is remount-skip (issue #92), not wrap apply failed"
        );
    }

    #[test]
    fn hide_root_is_not_shared_workpen_dest_deny() {
        let root = super::unique_hide_root().expect("mkdtemp");
        assert_ne!(
            root,
            std::env::temp_dir().join("workpen-dest-deny"),
            "hide dir must not be the planted shared path"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
