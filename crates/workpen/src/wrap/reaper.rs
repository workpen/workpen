//! Keep descendants from outliving the jailed command.
//!
//! `Command::process_group(0)` and a later `setsid` put the command in
//! its own group, so `killpg` of that group stops ordinary grandchildren.
//! A grandchild that calls `setsid` leaves the group. This module forks
//! once inside `pre_exec`: the parent is a reaper, the child is the
//! command. The reaper exits only after that command and the descendants
//! it can still see are gone.
//!
//! Linux sets `PR_SET_CHILD_SUBREAPER`, so a `setsid` grandchild is
//! reparented to the reaper when the command exits. macOS has no
//! subreaper. The reaper records descendants it observes while the
//! command is alive and signals those pids. A macOS command that forks
//! and exits before that observation can still leave a process behind.

use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

const MAX_PIDS: usize = 128;
const SCAN_NS: libc::c_long = 2_000_000;

static STOP: AtomicI32 = AtomicI32::new(0);

#[derive(Clone, Copy)]
struct Row {
    pid: libc::pid_t,
    // Start time is only compared on macOS. Linux identifies orphans
    // by `/proc` after they are reparented, so these fields are unused
    // there and `-D dead-code` rejects them.
    #[cfg(target_os = "macos")]
    sec: u64,
    #[cfg(target_os = "macos")]
    usec: u64,
}

struct Table {
    n: usize,
    rows: [Row; MAX_PIDS],
}

static mut TABLE: Table = Table {
    n: 0,
    rows: [Row {
        pid: 0,
        #[cfg(target_os = "macos")]
        sec: 0,
        #[cfg(target_os = "macos")]
        usec: 0,
    }; MAX_PIDS],
};

/// Fork a reaper. The command child returns `Ok`. The reaper does not
/// return.
///
/// Called only from `pre_exec`, which is already the single thread left
/// after `Command`'s fork. The reaper side uses libc only and `_exit`s.
pub(super) fn supervise_or_continue() -> io::Result<()> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        return Ok(());
    }
    reaper_main(pid);
}

fn reaper_main(cmd: libc::pid_t) -> ! {
    // Own process group so a later `killpg` of this pid cannot signal
    // the host. The command already inherited the previous group; PTY
    // `setsid` moves it again.
    unsafe {
        libc::setpgid(0, 0);
    }
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    }
    install_stop_handler();
    detach_stdio();
    // `Command::spawn` reads a CLOEXEC error pipe until exec. This
    // process does not exec, so close every extra fd or the parent
    // blocks in `spawn` until we exit.
    close_extra_fds();
    let mut status = 0;
    loop {
        if STOP.load(Ordering::Relaxed) != 0 {
            stop_for_signal(cmd);
        }
        remember_tree(cmd);
        let waited = unsafe { libc::waitpid(cmd, &mut status, libc::WNOHANG) };
        if waited == cmd {
            finish(cmd, status);
        }
        if waited < 0 && errno() == libc::ECHILD {
            kill_recorded();
            kill_adopted();
            drain_zombies();
            unsafe { libc::_exit(1) }
        }
        sleep_scan();
    }
}

fn stop_for_signal(cmd: libc::pid_t) -> ! {
    remember_tree(cmd);
    kill_recorded();
    unsafe {
        libc::kill(cmd, libc::SIGKILL);
    }
    let mut status = 0;
    for _ in 0..20 {
        let waited = unsafe { libc::waitpid(cmd, &mut status, libc::WNOHANG) };
        if waited == cmd {
            break;
        }
        sleep_scan();
    }
    kill_adopted();
    drain_zombies();
    unsafe { libc::_exit(128 + libc::SIGTERM) }
}

fn finish(cmd: libc::pid_t, status: libc::c_int) -> ! {
    remember_tree(cmd);
    kill_recorded();
    kill_adopted();
    drain_zombies();
    exit_like_command(status);
}

fn exit_like_command(status: libc::c_int) -> ! {
    if libc::WIFEXITED(status) {
        unsafe { libc::_exit(libc::WEXITSTATUS(status)) }
    }
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
            libc::_exit(128 + sig);
        }
    }
    unsafe { libc::_exit(1) }
}

/// Pid of the command process under `reaper`, once it is a group leader.
/// PTY setup uses this for `tcsetpgrp`. `None` if it never appears.
pub(super) fn leader_pid(reaper: libc::pid_t) -> Option<libc::pid_t> {
    for _ in 0..50 {
        if let Some(pid) = first_child(reaper) {
            let pg = unsafe { libc::getpgid(pid) };
            if pg == pid {
                return Some(pid);
            }
        }
        sleep_scan();
    }
    None
}

/// `true` when `pid` leads the process group `killpg` must target.
pub(super) fn is_group_leader(pid: libc::pid_t) -> bool {
    let pg = unsafe { libc::getpgid(pid) };
    pg == pid
}

fn first_child(pid: libc::pid_t) -> Option<libc::pid_t> {
    let mut kids = [0; 8];
    let n = direct_children(pid, &mut kids);
    if n == 0 { None } else { Some(kids[0]) }
}

fn install_stop_handler() {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_stop as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
    }
}

unsafe extern "C" fn on_stop(_sig: libc::c_int) {
    STOP.store(1, Ordering::Relaxed);
}

fn close_extra_fds() {
    let mut limit = libc::rlimit {
        rlim_cur: 1024,
        rlim_max: 1024,
    };
    unsafe {
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit);
    }
    // `RLIM_INFINITY` does not fit a useful scan. The exec-error pipe
    // is a low fd in practice; cap the walk so spawn stays cheap.
    let end = libc::c_int::try_from(limit.rlim_cur.min(4096)).unwrap_or(4096);
    if end <= 3 {
        return;
    }
    for fd in 3..end {
        unsafe {
            libc::close(fd);
        }
    }
}

fn detach_stdio() {
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return;
    }
    unsafe {
        libc::dup2(fd, 0);
        libc::dup2(fd, 1);
        libc::dup2(fd, 2);
        if fd > 2 {
            libc::close(fd);
        }
    }
}

fn sleep_scan() {
    let req = libc::timespec {
        tv_sec: 0,
        tv_nsec: SCAN_NS,
    };
    let mut rem = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::nanosleep(&req, &mut rem);
    }
}

fn remember_tree(root: libc::pid_t) {
    let mut stack = [0; MAX_PIDS];
    let mut sp = 0usize;
    let mut kids = [0; MAX_PIDS];
    let n = direct_children(root, &mut kids);
    for kid in kids.into_iter().take(n) {
        if sp < stack.len() {
            stack[sp] = kid;
            sp += 1;
        }
    }
    while sp > 0 {
        sp -= 1;
        let pid = stack[sp];
        remember(pid);
        let n = direct_children(pid, &mut kids);
        for kid in kids.into_iter().take(n) {
            if sp < stack.len() {
                stack[sp] = kid;
                sp += 1;
            }
        }
    }
}

fn remember(pid: libc::pid_t) {
    if pid <= 0 {
        return;
    }
    let table = unsafe { &mut *std::ptr::addr_of_mut!(TABLE) };
    if table.rows.iter().take(table.n).any(|row| row.pid == pid) {
        return;
    }
    if table.n >= MAX_PIDS {
        return;
    }
    #[cfg(target_os = "macos")]
    let (sec, usec) = start_time(pid).unwrap_or((0, 0));
    table.rows[table.n] = Row {
        pid,
        #[cfg(target_os = "macos")]
        sec,
        #[cfg(target_os = "macos")]
        usec,
    };
    table.n += 1;
}

fn errno() -> libc::c_int {
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location()
    }
    #[cfg(target_os = "macos")]
    unsafe {
        *libc::__error()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        0
    }
}

fn kill_recorded() {
    #[cfg(not(target_os = "macos"))]
    return;
    #[cfg(target_os = "macos")]
    {
        kill_recorded_macos();
    }
}

#[cfg(target_os = "macos")]
fn kill_recorded_macos() {
    let table = unsafe { &*std::ptr::addr_of!(TABLE) };
    let snapshot: [Row; MAX_PIDS] = table.rows;
    let n = table.n;
    for row in snapshot.into_iter().take(n) {
        if row.pid <= 0 {
            continue;
        }
        if !same_process(row) {
            continue;
        }
        unsafe {
            libc::kill(row.pid, libc::SIGKILL);
        }
    }
}

#[cfg(target_os = "macos")]
fn same_process(row: Row) -> bool {
    if row.sec == 0 && row.usec == 0 {
        // No start time. Only kill it while it is still our child or
        // the command's child. A recycled pid whose parent is init is
        // left alone.
        return parent_is_us_or_command(row.pid);
    }
    match start_time(row.pid) {
        Some((sec, usec)) => sec == row.sec && usec == row.usec,
        None => false,
    }
}

#[cfg(target_os = "macos")]
fn parent_is_us_or_command(pid: libc::pid_t) -> bool {
    let ppid = parent_pid(pid);
    if ppid <= 0 {
        return false;
    }
    ppid == unsafe { libc::getpid() } || child_of_command(ppid)
}

#[cfg(target_os = "macos")]
fn child_of_command(pid: libc::pid_t) -> bool {
    let me = unsafe { libc::getpid() };
    let mut kids = [0; MAX_PIDS];
    let n = direct_children(me, &mut kids);
    kids.into_iter().take(n).any(|kid| kid == pid)
}

fn kill_adopted() {
    // Linux subreaper: after the command exits, its orphans are our
    // children. Repeat so a grandchild's own children are adopted and
    // killed too. macOS does not reparent them here; `kill_recorded`
    // covers the pids observed earlier.
    for _ in 0..32 {
        let mut kids = [0; MAX_PIDS];
        let n = direct_children(unsafe { libc::getpid() }, &mut kids);
        if n == 0 {
            break;
        }
        for kid in kids.into_iter().take(n) {
            unsafe {
                libc::kill(kid, libc::SIGKILL);
            }
        }
        drain_zombies();
        sleep_scan();
    }
}

fn drain_zombies() {
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if waited <= 0 {
            break;
        }
    }
}

#[cfg(target_os = "macos")]
fn direct_children(pid: libc::pid_t, out: &mut [libc::pid_t]) -> usize {
    if out.is_empty() {
        return 0;
    }
    let n = unsafe {
        proc_listchildpids(
            pid,
            out.as_mut_ptr().cast(),
            std::mem::size_of_val(out) as libc::c_int,
        )
    };
    if n <= 0 {
        return 0;
    }
    let n = n as usize;
    if n > out.len() { out.len() } else { n }
}

#[cfg(target_os = "linux")]
fn direct_children(pid: libc::pid_t, out: &mut [libc::pid_t]) -> usize {
    let mut path = [0u8; 80];
    let Some(path) = children_path(pid, &mut path) else {
        return 0;
    };
    let fd = unsafe { libc::open(path, libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return 0;
    }
    let mut bytes = [0u8; 4096];
    let n = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
    unsafe {
        libc::close(fd);
    }
    if n <= 0 {
        return 0;
    }
    parse_pid_list(&bytes[..n as usize], out)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn direct_children(_pid: libc::pid_t, _out: &mut [libc::pid_t]) -> usize {
    0
}

#[cfg(target_os = "linux")]
fn children_path(pid: libc::pid_t, buf: &mut [u8; 80]) -> Option<*const libc::c_char> {
    let mut n = 0usize;
    for b in b"/proc/" {
        buf[n] = *b;
        n += 1;
    }
    push_u32(buf, &mut n, pid as u32);
    for b in b"/task/" {
        buf[n] = *b;
        n += 1;
    }
    push_u32(buf, &mut n, pid as u32);
    for b in b"/children\0" {
        buf[n] = *b;
        n += 1;
    }
    Some(buf.as_ptr().cast())
}

#[cfg(target_os = "linux")]
fn push_u32(buf: &mut [u8], n: &mut usize, mut value: u32) {
    let mut tmp = [0u8; 10];
    let mut i = 0usize;
    if value == 0 {
        tmp[0] = b'0';
        i = 1;
    } else {
        while value > 0 {
            tmp[i] = b'0' + (value % 10) as u8;
            i += 1;
            value /= 10;
        }
    }
    while i > 0 {
        i -= 1;
        buf[*n] = tmp[i];
        *n += 1;
    }
}

#[cfg(any(test, target_os = "linux"))]
fn parse_pid_list(bytes: &[u8], out: &mut [libc::pid_t]) -> usize {
    let mut n = 0usize;
    let mut cur: libc::pid_t = 0;
    let mut in_num = false;
    for byte in bytes {
        if byte.is_ascii_digit() {
            in_num = true;
            cur = cur
                .saturating_mul(10)
                .saturating_add((byte - b'0') as libc::pid_t);
        } else if in_num {
            if n < out.len() {
                out[n] = cur;
                n += 1;
            }
            cur = 0;
            in_num = false;
        }
    }
    if in_num && n < out.len() {
        out[n] = cur;
        n += 1;
    }
    n
}

#[cfg(target_os = "macos")]
fn start_time(pid: libc::pid_t) -> Option<(u64, u64)> {
    let mut buf = [0u8; 136];
    let n = unsafe {
        proc_pidinfo(
            pid as libc::c_int,
            3,
            0,
            buf.as_mut_ptr().cast(),
            buf.len() as libc::c_int,
        )
    };
    if n < 136 {
        return None;
    }
    let sec = u64::from_ne_bytes(buf[120..128].try_into().ok()?);
    let usec = u64::from_ne_bytes(buf[128..136].try_into().ok()?);
    Some((sec, usec))
}

#[cfg(target_os = "macos")]
fn parent_pid(pid: libc::pid_t) -> libc::pid_t {
    let mut buf = [0u8; 136];
    let n = unsafe {
        proc_pidinfo(
            pid as libc::c_int,
            3,
            0,
            buf.as_mut_ptr().cast(),
            buf.len() as libc::c_int,
        )
    };
    if n < 20 {
        return 0;
    }
    libc::pid_t::from_ne_bytes(buf[16..20].try_into().unwrap_or([0; 4]))
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
unsafe extern "C" {
    fn proc_listchildpids(
        ppid: libc::pid_t,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
}

#[cfg(test)]
mod tests {
    use super::parse_pid_list;

    #[test]
    fn parse_proc_children_list() {
        let mut out = [0; 4];
        let n = parse_pid_list(b"12 34 56\n", &mut out);
        assert_eq!(n, 3);
        assert_eq!(&out[..3], &[12, 34, 56]);
    }

    #[test]
    fn parse_proc_children_ignores_empty() {
        let mut out = [7; 2];
        let n = parse_pid_list(b" \n", &mut out);
        assert_eq!(n, 0);
    }
}
