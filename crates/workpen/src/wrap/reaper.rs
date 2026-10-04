//! Keep descendants from outliving the jailed command.
//!
//! `Command::process_group(0)` and a later `setsid` put the command in
//! its own group, so `killpg` of that group stops ordinary grandchildren.
//! A grandchild that calls `setsid` leaves the group. This module forks
//! once inside `pre_exec`: the parent is a reaper, the child is the
//! command. The reaper exits only after that command and the descendants
//! it can still see are gone.
//!
//! Linux sets `PR_SET_CHILD_SUBREAPER` before the reaper forks, so a
//! `setsid` grandchild is reparented here even when the command exits
//! before the first poll. An empty `/proc/.../children` read is not
//! proof that no child exists. macOS has no subreaper. The reaper
//! stops the command until a fork watch is armed,
//! records descendants from that watch and from walks, and signals those
//! pids. A pid that does not fit in the recorded set is reported on
//! `report_fd`. On macOS a fork whose parent has exited is reported
//! the same way when a live process with that command's name is still
//! outside the recorded set. The host turns that byte into
//! `KernelError::Descendants`.

use std::cell::RefCell;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

const MAX_PIDS: usize = 128;
const LIST_MAX: usize = 1024;
const SCAN_NS: libc::c_long = 2_000_000;
/// Empty child-list reads after the command has exited. One snapshot
/// can miss a grandchild that was reparented in that same exit.
#[cfg(target_os = "linux")]
const EMPTY_CHILD_POLLS: u32 = 4;
/// Polls of `proc_pidinfo` after continue. A short command can exit
/// before the reaper runs again, and a zombie no longer answers.
#[cfg(target_os = "macos")]
const IDENTITY_POLLS: usize = 4096;

static STOP: AtomicI32 = AtomicI32::new(0);
static mut MISSED: u8 = 0;

/// Parent ends of the reaper status pipe. `Send` so a host can finish
/// on another thread. `armed` is false when no reaper was installed.
pub(super) struct ReportPipe {
    read: Option<OwnedFd>,
    write: Option<OwnedFd>,
    pub(super) armed: bool,
}

thread_local! {
    static STASHED: RefCell<Option<ReportPipe>> = const { RefCell::new(None) };
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
static mut CMD_PID: libc::pid_t = 0;

/// Program name captured after exec. The reaper's own name is the
/// pre-exec image, so it must not be stored here.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct Identity {
    ready: u8,
    comm: [u8; 16],
    uid: u32,
    sec: u64,
    usec: u64,
}

#[cfg(target_os = "macos")]
static mut IDENT: Identity = Identity {
    ready: 0,
    comm: [0; 16],
    uid: 0,
    sec: 0,
    usec: 0,
};

#[cfg(target_os = "macos")]
static mut REAPER_COMM: [u8; 16] = [0; 16];

#[cfg(target_os = "macos")]
static mut REAPER_COMM_READY: u8 = 0;

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

impl ReportPipe {
    pub(super) fn write_raw(&self) -> i32 {
        self.write.as_ref().map(AsRawFd::as_raw_fd).unwrap_or(-1)
    }

    fn close_write(&mut self) {
        self.write.take();
    }

    /// `true` when the reaper reported a fully tracked tree.
    /// A timeout ignores the byte: the deadline result wins.
    /// An unarmed pipe is not a miss. Drop closes either way.
    pub(super) fn tracked(mut self, timed_out: bool) -> bool {
        if !self.armed {
            return true;
        }
        let read = self.read.take();
        drop(self.write.take());
        if timed_out {
            drop(read);
            return true;
        }
        let Some(read) = read else {
            return false;
        };
        let fd = read.as_raw_fd();
        let mut buf = [0u8; 1];
        let n = loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), 1) };
            if n < 0 && errno() == libc::EINTR {
                continue;
            }
            break n;
        };
        drop(read);
        n == 1 && buf[0] == 0
    }
}

impl Drop for ReportPipe {
    fn drop(&mut self) {
        self.write.take();
        self.read.take();
    }
}

/// Parent end of the reaper's one-byte status pipe.
/// `armed` even when `pipe` failed, so finish reports a miss.
pub(super) fn open_report() -> ReportPipe {
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return ReportPipe {
            read: None,
            write: None,
            armed: true,
        };
    }
    set_cloexec(fds[0]);
    set_cloexec(fds[1]);
    set_nonblock(fds[0]);
    // Safety: `pipe` just created both ends and no other owner exists.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    ReportPipe {
        read: Some(read),
        write: Some(write),
        armed: true,
    }
}

pub(super) fn unarmed_report() -> ReportPipe {
    ReportPipe {
        read: None,
        write: None,
        armed: false,
    }
}

/// Same-thread `apply_pre_exec` keeps the pipe here. A second stash
/// drops the previous pipe. The `Send` report path does not call this.
pub(super) fn stash_report(report: ReportPipe) {
    let prev = STASHED.with(|slot| slot.borrow_mut().replace(report));
    drop(prev);
}

pub(super) fn close_parent_report_write() {
    STASHED.with(|slot| {
        if let Some(report) = slot.borrow_mut().as_mut() {
            report.close_write();
        }
    });
}

pub(super) fn discard_report() {
    let prev = STASHED.with(|slot| slot.borrow_mut().take());
    drop(prev);
}

/// `true` when the reaper reported a fully tracked tree.
/// A timeout ignores the byte: the deadline result wins.
/// No stashed pipe is a miss, unless the deadline already fired.
pub(super) fn take_descendant_report(timed_out: bool) -> bool {
    match STASHED.with(|slot| slot.borrow_mut().take()) {
        Some(report) => report.tracked(timed_out),
        None => timed_out,
    }
}

/// Fork a reaper. The command child returns `Ok`. The reaper does not
/// return.
///
/// Called only from `pre_exec`, which is already the single thread left
/// after `Command`'s fork. The reaper side uses libc only and `_exit`s.
/// `report_fd` is the write end, captured by value. The parent's
/// `OwnedFd` stays in the parent. After `fork` the child has its own
/// copy of that descriptor.
pub(super) fn supervise_or_continue(report_fd: i32) -> io::Result<()> {
    // `fork` returns into the command immediately. This process is the
    // reaper, so the subreaper flag has to be set first or a `setsid`
    // grandchild whose parent exits in that window is reparented to
    // pid 1. The child list stays empty and the reaper exits 0.
    // The command inherits `has_child_subreaper`, which is what makes
    // the kernel walk up to this process.
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
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
    // Subreaper was set before the fork. Setting it here is after the
    // command is already running.
    reset_tracking();
    #[cfg(target_os = "macos")]
    unsafe {
        std::ptr::addr_of_mut!(CMD_PID).write(cmd);
    }
    install_stop_handler();
    detach_stdio();
    let kq = watch_command(cmd, report_fd);
    // `Command::spawn` reads a CLOEXEC error pipe until exec. This
    // process does not exec, so close every extra fd or the parent
    // blocks in `spawn` until we exit. Keep the report and the watch.
    // On macOS the command is still stopped here. Continuing first lets
    // a setsid child exit during the walk.
    close_extra_fds(report_fd, kq);
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::kill(cmd, libc::SIGCONT) };
        cache_command_identity(cmd);
    }
    drain_proc_events(kq);
    let mut status = 0;
    loop {
        if STOP.load(Ordering::Relaxed) != 0 {
            stop_for_signal(cmd, report_fd, kq);
        }
        drain_proc_events(kq);
        remember_tree(cmd, kq);
        #[cfg(target_os = "macos")]
        remember_identity(cmd);
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
        return -1;
    }
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

/// Set `FD_CLOEXEC` on inherited descriptors above stdio.
///
/// `exec` drops them, so `cat <&3` cannot read a secret the parent
/// still has open. Closing the descriptor here would also close the
/// PTY slave and the stdout pipe before Rust `dup2`s them onto stdio.
/// Descriptors that already have `FD_CLOEXEC` (the spawn error pipe
/// and the reaper report) are left alone. The scan stops at 4096,
/// same as [`close_extra_fds`].
pub(super) fn cloexec_inherited_fds() {
    let mut limit = libc::rlimit {
        rlim_cur: 1024,
        rlim_max: 1024,
    };
    unsafe {
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit);
    }
    let end = libc::c_int::try_from(limit.rlim_cur.min(4096)).unwrap_or(4096);
    if end <= 3 {
        return;
    }
    for fd in 3..end {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
            unsafe {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }
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
    //
    // A count above MAX_PIDS did not fit in the recorded set, even
    // when the poll never saw those pids before the command exited.
    let mut kills = 0u32;
    let mut empty = 0u32;
    let empty_limit = empty_child_polls();
    while kills < 32 {
        let mut kids = [0; LIST_MAX];
        let (n, trunc) = direct_children(unsafe { libc::getpid() }, &mut kids);
        if trunc || n > MAX_PIDS {
            mark_missed();
        }
        if n == 0 {
            if empty >= empty_limit {
                break;
            }
            empty += 1;
            sleep_scan();
            continue;
        }
        empty = 0;
        kills += 1;
        for kid in kids.into_iter().take(n) {
            unsafe {
                libc::kill(kid, libc::SIGKILL);
            }
        }
        drain_zombies();
        sleep_scan();
    }
}

fn empty_child_polls() -> u32 {
    #[cfg(target_os = "linux")]
    {
        EMPTY_CHILD_POLLS
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
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
    if rc == 0 || (rc < 0 && errno() == libc::EEXIST) {
        return true;
    }
    // A zombie still answers kill(pid, 0), and proc_pidinfo returns
    // nothing. It cannot fork. A pid that is already gone can have
    // left a setsid child, so that case stays a miss. Do not call
    // proc_pidinfo on the stopped command: that call does not return
    // before SIGCONT.
    if rc < 0 && errno() == libc::ESRCH {
        let cmd = unsafe { std::ptr::addr_of!(CMD_PID).read() };
        if pid != cmd && proc_info_missing(pid) {
            return true;
        }
    }
    false
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
    }
}

#[cfg(target_os = "macos")]
fn on_fork(parent: libc::pid_t, kq: i32, also_exit: bool) {
    remember_identity(parent);
    let cmd = unsafe { std::ptr::addr_of!(CMD_PID).read() };
    remember_identity(cmd);
    let mut kids = [0; LIST_MAX];
    let (mut n, trunc) = direct_children(parent, &mut kids);
    if trunc {
        mark_missed();
    }
    if n == 0 && !also_exit && !parent_is_gone(parent) {
        // The child may not be linked yet. A few rereads catch that.
        // A helper the parent already waited for stays absent.
        for _ in 0..16 {
            let (n2, trunc2) = direct_children(parent, &mut kids);
            if trunc2 {
                mark_missed();
            }
            if n2 > 0 {
                n = n2;
                break;
            }
            if parent_is_gone(parent) {
                break;
            }
        }
    }
    if n > 0 {
        note_seen(parent);
        for kid in kids.into_iter().take(n) {
            note_pid(kid, kq);
        }
        return;
    }
    // setsid does not drop a live child while this parent still exists.
    if !also_exit && !parent_is_gone(parent) {
        return;
    }
    // Reparented. Report only a live process that still has this
    // command's name. Do not signal an unmatched pid.
    if untracked_same_name(parent) {
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
fn proc_info_missing(pid: libc::pid_t) -> bool {
    if pid <= 0 || unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
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
    n < 8
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

#[cfg(target_os = "macos")]
fn identity_ready() -> bool {
    unsafe { std::ptr::addr_of!(IDENT).read().ready != 0 }
}

/// `proc_pidinfo` on a zombie returns nothing. Read the name while the
/// command is still alive, and skip the pre-exec image.
#[cfg(target_os = "macos")]
fn remember_identity(pid: libc::pid_t) {
    if pid <= 0 || identity_ready() {
        return;
    }
    let Some(info) = bsdinfo(pid) else {
        return;
    };
    let comm = &info[48..64];
    if comm.iter().all(|byte| *byte == 0) {
        return;
    }
    let Some(mine) = reaper_comm() else {
        return;
    };
    if comm == mine.as_slice() {
        return;
    }
    let sec = u64::from_ne_bytes(info[120..128].try_into().unwrap_or([0; 8]));
    let usec = u64::from_ne_bytes(info[128..136].try_into().unwrap_or([0; 8]));
    // A zero start would match every later process with this name.
    if sec == 0 && usec == 0 {
        return;
    }
    unsafe {
        let ident = &mut *std::ptr::addr_of_mut!(IDENT);
        ident.comm.copy_from_slice(comm);
        ident.uid = u32::from_ne_bytes(info[20..24].try_into().unwrap_or([0; 4]));
        ident.sec = sec;
        ident.usec = usec;
        ident.ready = 1;
    }
}

#[cfg(target_os = "macos")]
fn reaper_comm() -> Option<[u8; 16]> {
    unsafe {
        if std::ptr::addr_of!(REAPER_COMM_READY).read() == 0 {
            let info = bsdinfo(libc::getpid())?;
            (*std::ptr::addr_of_mut!(REAPER_COMM)).copy_from_slice(&info[48..64]);
            std::ptr::addr_of_mut!(REAPER_COMM_READY).write(1);
        }
        Some(std::ptr::addr_of!(REAPER_COMM).read())
    }
}

#[cfg(target_os = "macos")]
fn cache_command_identity(cmd: libc::pid_t) {
    for _ in 0..IDENTITY_POLLS {
        if identity_ready() {
            return;
        }
        remember_identity(cmd);
        if identity_ready() || unsafe { libc::kill(cmd, 0) } != 0 {
            return;
        }
    }
}

/// Live launchd child with this command's name, started with the
/// command, and not already recorded. A full child buffer is a miss:
/// the orphan may sit past the end.
#[cfg(target_os = "macos")]
fn untracked_same_name(parent: libc::pid_t) -> bool {
    remember_identity(parent);
    let cmd = unsafe { std::ptr::addr_of!(CMD_PID).read() };
    remember_identity(cmd);
    if !identity_ready() {
        return false;
    }
    let ident = unsafe { std::ptr::addr_of!(IDENT).read() };
    if ident.sec == 0 && ident.usec == 0 {
        return false;
    }
    let me = unsafe { libc::getpid() };
    let mut kids = [0; 4096];
    let (n, trunc) = direct_children(1, &mut kids);
    for pid in kids.into_iter().take(n) {
        if pid <= 0 || pid == cmd || pid == me || pid == parent || is_recorded(pid) {
            continue;
        }
        let Some(info) = bsdinfo(pid) else {
            continue;
        };
        let status = u32::from_ne_bytes(info[4..8].try_into().unwrap_or([0; 4]));
        if status == 5 || &info[48..64] != ident.comm.as_slice() {
            continue;
        }
        let ouid = u32::from_ne_bytes(info[20..24].try_into().unwrap_or([0; 4]));
        if ouid != ident.uid {
            continue;
        }
        let stamp = (
            u64::from_ne_bytes(info[120..128].try_into().unwrap_or([0; 8])),
            u64::from_ne_bytes(info[128..136].try_into().unwrap_or([0; 8])),
        );
        if stamp.0 == 0 && stamp.1 == 0 {
            continue;
        }
        if stamp >= (ident.sec, ident.usec) {
            return true;
        }
    }
    trunc
}

#[cfg(target_os = "macos")]
fn bsdinfo(pid: libc::pid_t) -> Option<[u8; 136]> {
    if pid <= 0 {
        return None;
    }
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
    if n < 136 { None } else { Some(buf) }
}

#[cfg(target_os = "macos")]
fn is_recorded(pid: libc::pid_t) -> bool {
    let table = unsafe { &*std::ptr::addr_of!(TABLE) };
    if table.rows[..table.n].iter().any(|row| row.pid == pid) {
        return true;
    }
    let over = unsafe { &*std::ptr::addr_of!(OVERFLOW) };
    over.rows[..over.n].iter().any(|row| row.pid == pid)
}

fn reset_tracking() {
    unsafe {
        std::ptr::addr_of_mut!(MISSED).write(0);
        let table = &mut *std::ptr::addr_of_mut!(TABLE);
        table.n = 0;
        #[cfg(target_os = "macos")]
        {
            (*std::ptr::addr_of_mut!(OVERFLOW)).n = 0;
            (*std::ptr::addr_of_mut!(SEEN)).n = 0;
            std::ptr::addr_of_mut!(CMD_PID).write(0);
            std::ptr::addr_of_mut!(IDENT).write(Identity {
                ready: 0,
                comm: [0; 16],
                uid: 0,
                sec: 0,
                usec: 0,
            });
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
    #[cfg(target_os = "macos")]
    if untracked_same_name(0) {
        mark_missed();
    }
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

    #[test]
    fn report_byte_zero_is_tracked_and_one_is_a_miss() {
        let report = super::open_report();
        let write = report.write_raw();
        let ok = [0u8];
        assert_eq!(unsafe { libc::write(write, ok.as_ptr().cast(), 1) }, 1);
        assert!(report.tracked(false));

        let report = super::open_report();
        let write = report.write_raw();
        let miss = [1u8];
        assert_eq!(unsafe { libc::write(write, miss.as_ptr().cast(), 1) }, 1);
        assert!(!report.tracked(false));
    }

    #[test]
    fn report_timeout_and_unarmed_pipe_are_not_misses() {
        let report = super::open_report();
        assert!(report.tracked(true));
        assert!(super::unarmed_report().tracked(false));
    }
}
