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
//! subreaper. The reaper stops the command until a fork watch is armed,
//! records descendants from that watch and from walks, and signals those
//! pids. A pid that does not fit in the recorded set, or a fork whose
//! new pid is no longer listed, is reported on `report_fd`. The host
//! turns that byte into `KernelError::Descendants`.

use std::cell::Cell;
use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

const MAX_PIDS: usize = 128;
const LIST_MAX: usize = 1024;
const SCAN_NS: libc::c_long = 2_000_000;

static STOP: AtomicI32 = AtomicI32::new(0);
static mut MISSED: u8 = 0;

thread_local! {
    static REPORT_READ: Cell<i32> = const { Cell::new(-1) };
    static REPORT_WRITE: Cell<i32> = const { Cell::new(-1) };
}

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

#[cfg(target_os = "macos")]
struct Overflow {
    n: usize,
    rows: [Row; LIST_MAX],
}

#[cfg(target_os = "macos")]
static mut OVERFLOW: Overflow = Overflow {
    n: 0,
    rows: [Row {
        pid: 0,
        sec: 0,
        usec: 0,
    }; LIST_MAX],
};

#[cfg(target_os = "macos")]
struct PidSet {
    n: usize,
    pids: [libc::pid_t; MAX_PIDS + 1],
}

#[cfg(target_os = "macos")]
static mut PENDING: PidSet = PidSet {
    n: 0,
    pids: [0; MAX_PIDS + 1],
};

#[cfg(target_os = "macos")]
static mut SEEN: PidSet = PidSet {
    n: 0,
    pids: [0; MAX_PIDS + 1],
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Remember {
    Stored,
    Already,
    Full,
}

/// Parent end of the reaper's one-byte status pipe. `-1` if `pipe` failed.
pub(super) fn prepare_report() -> i32 {
    discard_report();
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return -1;
    }
    for fd in fds {
        set_cloexec(fd);
    }
    set_nonblock(fds[0]);
    REPORT_READ.set(fds[0]);
    REPORT_WRITE.set(fds[1]);
    fds[1]
}

pub(super) fn close_parent_report_write() {
    let fd = REPORT_WRITE.replace(-1);
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

pub(super) fn discard_report() {
    close_parent_report_write();
    let fd = REPORT_READ.replace(-1);
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

/// `true` when the reaper reported a fully tracked tree.
/// A timeout ignores the byte: the deadline result wins.
pub(super) fn take_descendant_report(timed_out: bool) -> bool {
    let read_fd = REPORT_READ.replace(-1);
    close_parent_report_write();
    if timed_out {
        if read_fd >= 0 {
            unsafe { libc::close(read_fd) };
        }
        return true;
    }
    if read_fd < 0 {
        return false;
    }
    let mut buf = [0u8; 1];
    let n = loop {
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), 1) };
        if n < 0 && errno() == libc::EINTR {
            continue;
        }
        break n;
    };
    unsafe { libc::close(read_fd) };
    n == 1 && buf[0] == 0
}

/// Fork a reaper. The command child returns `Ok`. The reaper does not
/// return.
///
/// Called only from `pre_exec`, which is already the single thread left
/// after `Command`'s fork. The reaper side uses libc only and `_exit`s.
/// `report_fd` is the write end, captured by value so the child does not
/// read the parent's thread-local after this fork.
pub(super) fn supervise_or_continue(report_fd: i32) -> io::Result<()> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // Stop before any later `pre_exec` hook or the command's own
        // fork. The reaper arms a watch, then continues this process.
        #[cfg(target_os = "macos")]
        unsafe {
            libc::raise(libc::SIGSTOP);
        }
        return Ok(());
    }
    reaper_main(pid, report_fd);
}

fn reaper_main(cmd: libc::pid_t, report_fd: i32) -> ! {
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
    reset_tracking();
    install_stop_handler();
    detach_stdio();
    let kq = watch_command(cmd, report_fd);
    // The command is already running. Read fork notes before the fd
    // walk so a short helper is still in the child list.
    drain_proc_events(kq);
    // `Command::spawn` reads a CLOEXEC error pipe until exec. This
    // process does not exec, so close every extra fd or the parent
    // blocks in `spawn` until we exit. Keep the report and the watch.
    close_extra_fds(report_fd, kq);
    let mut status = 0;
    loop {
        if STOP.load(Ordering::Relaxed) != 0 {
            stop_for_signal(cmd, report_fd, kq);
        }
        drain_proc_events(kq);
        remember_tree(cmd, kq);
        let waited = unsafe { libc::waitpid(cmd, &mut status, libc::WNOHANG) };
        if waited == cmd {
            finish(cmd, status, report_fd, kq);
        }
        if waited < 0 && errno() == libc::ECHILD {
            kill_recorded();
            kill_adopted();
            drain_zombies();
            write_report(report_fd);
            close_kq(kq);
            unsafe { libc::_exit(1) }
        }
        block_until_scan(kq);
    }
}

fn stop_for_signal(cmd: libc::pid_t, report_fd: i32, kq: i32) -> ! {
    drain_proc_events(kq);
    remember_tree(cmd, kq);
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
        block_until_scan(kq);
        drain_proc_events(kq);
        remember_tree(cmd, kq);
    }
    kill_adopted();
    drain_zombies();
    write_report(report_fd);
    close_kq(kq);
    unsafe { libc::_exit(128 + libc::SIGTERM) }
}

fn finish(cmd: libc::pid_t, status: libc::c_int, report_fd: i32, kq: i32) -> ! {
    drain_proc_events(kq);
    remember_tree(cmd, kq);
    kill_recorded();
    kill_adopted();
    drain_zombies();
    write_report(report_fd);
    close_kq(kq);
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

fn watch_command(cmd: libc::pid_t, report_fd: i32) -> i32 {
    #[cfg(target_os = "macos")]
    {
        watch_command_macos(cmd, report_fd)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (cmd, report_fd);
        -1
    }
}

#[cfg(target_os = "macos")]
fn watch_command_macos(cmd: libc::pid_t, report_fd: i32) -> i32 {
    let Some(status) = wait_until_stopped(cmd) else {
        // No fork watch. Polling alone can miss a setsid child.
        mark_missed();
        if STOP.load(Ordering::Relaxed) != 0 {
            stop_for_signal(cmd, report_fd, -1);
        }
        return -1;
    };
    if !libc::WIFSTOPPED(status) {
        finish(cmd, status, report_fd, -1);
    }
    let kq = unsafe { libc::kqueue() };
    if kq < 0 || !arm_knote_macos(kq, cmd) {
        mark_missed();
        if kq >= 0 {
            unsafe { libc::close(kq) };
        }
        unsafe { libc::kill(cmd, libc::SIGCONT) };
        return -1;
    }
    unsafe { libc::kill(cmd, libc::SIGCONT) };
    kq
}

#[cfg(target_os = "macos")]
fn wait_until_stopped(cmd: libc::pid_t) -> Option<libc::c_int> {
    let mut status = 0;
    loop {
        if STOP.load(Ordering::Relaxed) != 0 {
            unsafe { libc::kill(cmd, libc::SIGCONT) };
            return None;
        }
        let waited = unsafe { libc::waitpid(cmd, &mut status, libc::WUNTRACED) };
        if waited == cmd {
            return Some(status);
        }
        if waited < 0 && errno() == libc::EINTR {
            continue;
        }
        unsafe { libc::kill(cmd, libc::SIGCONT) };
        return None;
    }
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
    let (n, _) = direct_children(pid, &mut kids);
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

fn close_extra_fds(keep_a: i32, keep_b: i32) {
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
        if fd == keep_a || fd == keep_b {
            continue;
        }
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

fn remember_tree(root: libc::pid_t, kq: i32) {
    let mut stack = [0; LIST_MAX];
    let mut sp = 0usize;
    let mut kids = [0; LIST_MAX];
    push_children(root, kq, &mut kids, &mut stack, &mut sp);
    while sp > 0 {
        sp -= 1;
        let pid = stack[sp];
        note_pid(pid, kq);
        push_children(pid, kq, &mut kids, &mut stack, &mut sp);
    }
}

fn push_children(
    pid: libc::pid_t,
    kq: i32,
    kids: &mut [libc::pid_t; LIST_MAX],
    stack: &mut [libc::pid_t; LIST_MAX],
    sp: &mut usize,
) {
    let (n, trunc) = direct_children(pid, kids);
    if trunc {
        mark_missed();
    }
    if n > 0 {
        #[cfg(target_os = "macos")]
        note_seen(pid);
    }
    for kid in kids.iter().take(n).copied() {
        if *sp < stack.len() {
            stack[*sp] = kid;
            *sp += 1;
        } else {
            note_pid(kid, kq);
            mark_missed();
        }
    }
}

fn note_pid(pid: libc::pid_t, kq: i32) -> Remember {
    let stored = remember(pid);
    if stored == Remember::Stored && !arm_knote(kq, pid) {
        // This pid can fork again. Without a knote, that child is untracked.
        mark_missed();
    }
    stored
}

fn remember(pid: libc::pid_t) -> Remember {
    if pid <= 0 {
        return Remember::Already;
    }
    let table = unsafe { &mut *std::ptr::addr_of_mut!(TABLE) };
    if table.rows.iter().take(table.n).any(|row| row.pid == pid) {
        return Remember::Already;
    }
    if table.n >= MAX_PIDS {
        mark_missed();
        save_overflow(pid);
        return Remember::Full;
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
    Remember::Stored
}

fn save_overflow(pid: libc::pid_t) {
    #[cfg(target_os = "macos")]
    {
        let over = unsafe { &mut *std::ptr::addr_of_mut!(OVERFLOW) };
        if over.rows.iter().take(over.n).any(|row| row.pid == pid) {
            return;
        }
        if over.n >= LIST_MAX {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            return;
        }
        let (sec, usec) = start_time(pid).unwrap_or((0, 0));
        over.rows[over.n] = Row { pid, sec, usec };
        over.n += 1;
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
    }
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
    let recorded: [Row; MAX_PIDS] = table.rows;
    let recorded_n = table.n;
    kill_rows(&recorded[..recorded_n]);
    let over = unsafe { &*std::ptr::addr_of!(OVERFLOW) };
    let n = over.n;
    for i in 0..n {
        let row = unsafe { (*std::ptr::addr_of!(OVERFLOW)).rows[i] };
        kill_row(row);
    }
}

#[cfg(target_os = "macos")]
fn kill_rows(rows: &[Row]) {
    for row in rows {
        kill_row(*row);
    }
}

#[cfg(target_os = "macos")]
fn kill_row(row: Row) {
    if row.pid <= 0 || !same_process(row) {
        return;
    }
    unsafe {
        libc::kill(row.pid, libc::SIGKILL);
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
    let mut kids = [0; LIST_MAX];
    let (n, trunc) = direct_children(me, &mut kids);
    if trunc {
        mark_missed();
    }
    kids.into_iter().take(n).any(|kid| kid == pid)
}

fn kill_adopted() {
    // Linux subreaper: after the command exits, its orphans are our
    // children. Repeat so a grandchild's own children are adopted and
    // killed too. macOS does not reparent them here; `kill_recorded`
    // covers the pids observed earlier.
    for _ in 0..32 {
        let mut kids = [0; LIST_MAX];
        let (n, trunc) = direct_children(unsafe { libc::getpid() }, &mut kids);
        if trunc {
            mark_missed();
        }
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

fn direct_children(pid: libc::pid_t, out: &mut [libc::pid_t]) -> (usize, bool) {
    #[cfg(target_os = "macos")]
    {
        direct_children_macos(pid, out)
    }
    #[cfg(target_os = "linux")]
    {
        direct_children_linux(pid, out)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (pid, out);
        (0, false)
    }
}

#[cfg(target_os = "macos")]
fn direct_children_macos(pid: libc::pid_t, out: &mut [libc::pid_t]) -> (usize, bool) {
    if out.is_empty() {
        return (0, true);
    }
    let n = unsafe {
        proc_listchildpids(
            pid,
            out.as_mut_ptr().cast(),
            std::mem::size_of_val(out) as libc::c_int,
        )
    };
    if n <= 0 {
        return (0, false);
    }
    let n = n as usize;
    if n > out.len() {
        (out.len(), true)
    } else {
        (n, false)
    }
}

#[cfg(target_os = "linux")]
fn direct_children_linux(pid: libc::pid_t, out: &mut [libc::pid_t]) -> (usize, bool) {
    let mut path = [0u8; 80];
    let Some(path) = children_path(pid, &mut path) else {
        return (0, false);
    };
    let fd = unsafe { libc::open(path, libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return (0, false);
    }
    let mut bytes = [0u8; 4096];
    let n = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
    unsafe {
        libc::close(fd);
    }
    if n <= 0 {
        return (0, false);
    }
    let nread = n as usize;
    let filled = nread == bytes.len();
    let (count, overflow) = parse_pid_list(&bytes[..nread], out);
    (count, overflow || filled)
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
fn parse_pid_list(bytes: &[u8], out: &mut [libc::pid_t]) -> (usize, bool) {
    let mut n = 0usize;
    let mut cur: libc::pid_t = 0;
    let mut in_num = false;
    let mut overflow = false;
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
            } else {
                overflow = true;
            }
            cur = 0;
            in_num = false;
        }
    }
    if in_num {
        if n < out.len() {
            out[n] = cur;
            n += 1;
        } else {
            overflow = true;
        }
    }
    (n, overflow)
}

fn drain_proc_events(kq: i32) {
    #[cfg(target_os = "macos")]
    {
        if kq < 0 {
            return;
        }
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        for _ in 0..256 {
            if !next_event(kq, &zero) {
                break;
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = kq;
    }
}

fn block_until_scan(kq: i32) {
    if waited_on_kqueue(kq) {
        return;
    }
    sleep_scan();
}

fn waited_on_kqueue(kq: i32) -> bool {
    #[cfg(target_os = "macos")]
    {
        if kq < 0 {
            return false;
        }
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: SCAN_NS,
        };
        let _ = next_event(kq, &ts);
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = kq;
        false
    }
}

fn arm_knote(kq: i32, pid: libc::pid_t) -> bool {
    #[cfg(target_os = "macos")]
    {
        arm_knote_macos(kq, pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (kq, pid);
        true
    }
}

#[cfg(target_os = "macos")]
fn arm_knote_macos(kq: i32, pid: libc::pid_t) -> bool {
    if kq < 0 || pid <= 0 {
        return false;
    }
    let mut ev: libc::kevent = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::addr_of_mut!(ev.ident).write(pid as libc::uintptr_t);
        std::ptr::addr_of_mut!(ev.filter).write(libc::EVFILT_PROC);
        std::ptr::addr_of_mut!(ev.flags).write(libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR);
        std::ptr::addr_of_mut!(ev.fflags).write(libc::NOTE_FORK | libc::NOTE_EXIT);
    }
    let rc = unsafe {
        libc::kevent(
            kq,
            std::ptr::addr_of!(ev),
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    rc == 0 || (rc < 0 && errno() == libc::EEXIST)
}

#[cfg(target_os = "macos")]
fn next_event(kq: i32, timeout: *const libc::timespec) -> bool {
    let mut ev: libc::kevent = unsafe { std::mem::zeroed() };
    let n = unsafe {
        libc::kevent(
            kq,
            std::ptr::null(),
            0,
            std::ptr::addr_of_mut!(ev),
            1,
            timeout,
        )
    };
    if n <= 0 {
        return false;
    }
    handle_event(&ev, kq);
    true
}

#[cfg(target_os = "macos")]
fn handle_event(ev: &libc::kevent, kq: i32) {
    let flags = unsafe { std::ptr::addr_of!(ev.flags).read() };
    if flags & libc::EV_ERROR != 0 {
        return;
    }
    let fflags = unsafe { std::ptr::addr_of!(ev.fflags).read() };
    let ident = unsafe { std::ptr::addr_of!(ev.ident).read() } as libc::pid_t;
    let note_fork = fflags & libc::NOTE_FORK != 0;
    let note_exit = fflags & libc::NOTE_EXIT != 0;
    if note_fork {
        on_fork(ident, kq, note_exit);
    } else if note_exit {
        on_exit(ident);
    }
}

#[cfg(target_os = "macos")]
fn on_fork(parent: libc::pid_t, kq: i32, also_exit: bool) {
    let mut kids = [0; LIST_MAX];
    let (n, trunc) = direct_children(parent, &mut kids);
    if trunc {
        mark_missed();
    }
    if n > 0 {
        clear_pending(parent);
        note_seen(parent);
        for kid in kids.into_iter().take(n) {
            note_pid(kid, kq);
        }
        return;
    }
    // This fork's pid is already gone. Once the parent has exited it
    // was reparented, even if an older sibling is in the table.
    if also_exit || parent_is_gone(parent) {
        mark_missed();
        clear_pending(parent);
        return;
    }
    if !has_seen(parent) {
        set_pending(parent);
    }
}

#[cfg(target_os = "macos")]
fn on_exit(parent: libc::pid_t) {
    if take_pending(parent) && !has_seen(parent) {
        mark_missed();
    }
}

#[cfg(target_os = "macos")]
fn note_seen(pid: libc::pid_t) {
    let seen = unsafe { &mut *std::ptr::addr_of_mut!(SEEN) };
    if !pidset_insert(seen, pid) {
        mark_missed();
    }
}

#[cfg(target_os = "macos")]
fn has_seen(pid: libc::pid_t) -> bool {
    let seen = unsafe { &*std::ptr::addr_of!(SEEN) };
    pidset_contains(seen, pid)
}

#[cfg(target_os = "macos")]
fn set_pending(pid: libc::pid_t) {
    let pending = unsafe { &mut *std::ptr::addr_of_mut!(PENDING) };
    if !pidset_insert(pending, pid) {
        mark_missed();
    }
}

#[cfg(target_os = "macos")]
fn clear_pending(pid: libc::pid_t) {
    let pending = unsafe { &mut *std::ptr::addr_of_mut!(PENDING) };
    pidset_remove(pending, pid);
}

#[cfg(target_os = "macos")]
fn take_pending(pid: libc::pid_t) -> bool {
    let pending = unsafe { &mut *std::ptr::addr_of_mut!(PENDING) };
    pidset_remove(pending, pid)
}

#[cfg(target_os = "macos")]
fn pidset_contains(set: &PidSet, pid: libc::pid_t) -> bool {
    set.pids[..set.n].contains(&pid)
}

#[cfg(target_os = "macos")]
fn pidset_insert(set: &mut PidSet, pid: libc::pid_t) -> bool {
    if pid <= 0 || pidset_contains(set, pid) {
        return true;
    }
    if set.n >= set.pids.len() {
        return false;
    }
    set.pids[set.n] = pid;
    set.n += 1;
    true
}

#[cfg(target_os = "macos")]
fn pidset_remove(set: &mut PidSet, pid: libc::pid_t) -> bool {
    let Some(i) = set.pids[..set.n].iter().position(|item| *item == pid) else {
        return false;
    };
    set.n -= 1;
    set.pids[i] = set.pids[set.n];
    true
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
fn parent_is_gone(pid: libc::pid_t) -> bool {
    if pid <= 0 {
        return true;
    }
    if unsafe { libc::kill(pid, 0) } != 0 {
        return true;
    }
    // Second `u32` of `proc_bsdinfo` is `pbi_status`. 5 is `SZOMB`.
    let mut buf = [0u8; 8];
    let n = unsafe {
        proc_pidinfo(
            pid as libc::c_int,
            3,
            0,
            buf.as_mut_ptr().cast(),
            buf.len() as libc::c_int,
        )
    };
    if n < 8 {
        return false;
    }
    u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) == 5
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

fn reset_tracking() {
    unsafe {
        std::ptr::addr_of_mut!(MISSED).write(0);
        let table = &mut *std::ptr::addr_of_mut!(TABLE);
        table.n = 0;
        #[cfg(target_os = "macos")]
        {
            (*std::ptr::addr_of_mut!(OVERFLOW)).n = 0;
            (*std::ptr::addr_of_mut!(PENDING)).n = 0;
            (*std::ptr::addr_of_mut!(SEEN)).n = 0;
        }
    }
}

fn mark_missed() {
    unsafe { std::ptr::addr_of_mut!(MISSED).write(1) }
}

fn missed() -> bool {
    unsafe { std::ptr::addr_of!(MISSED).read() != 0 }
}

fn write_report(fd: i32) {
    if fd < 0 {
        return;
    }
    let byte = [u8::from(missed())];
    let mut off = 0usize;
    while off < byte.len() {
        let n = unsafe { libc::write(fd, byte[off..].as_ptr().cast(), byte.len() - off) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            break;
        }
        if n == 0 {
            break;
        }
        off += n as usize;
    }
    unsafe { libc::close(fd) };
}

fn close_kq(kq: i32) {
    if kq >= 0 {
        unsafe { libc::close(kq) };
    }
}

fn set_cloexec(fd: i32) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

fn set_nonblock(fd: i32) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_pid_list;

    #[test]
    fn parse_proc_children_list() {
        let mut out = [0; 4];
        let (n, overflow) = parse_pid_list(b"12 34 56\n", &mut out);
        assert_eq!(n, 3);
        assert!(!overflow);
        assert_eq!(&out[..3], &[12, 34, 56]);
    }

    #[test]
    fn parse_proc_children_ignores_empty() {
        let mut out = [7; 2];
        let (n, overflow) = parse_pid_list(b" \n", &mut out);
        assert_eq!(n, 0);
        assert!(!overflow);
    }

    #[test]
    fn parse_proc_children_reports_overflow() {
        let mut out = [0; 2];
        let (n, overflow) = parse_pid_list(b"12 34 56\n", &mut out);
        assert_eq!(n, 2);
        assert!(overflow);
        assert_eq!(&out[..2], &[12, 34]);
    }
}
