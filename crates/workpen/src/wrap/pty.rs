//! Unix PTY for `workpen run --tty`. Opened in the parent; the child
//! inherits the slave as stdin/stdout/stderr.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;

static PTSNAME_LOCK: Mutex<()> = Mutex::new(());

pub(super) struct Pty {
    pub master: File,
    pub slave: File,
}

pub(super) fn open_pty() -> io::Result<Pty> {
    let master_fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::grantpt(master_fd) } != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(master_fd) };
        return Err(err);
    }
    if unsafe { libc::unlockpt(master_fd) } != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(master_fd) };
        return Err(err);
    }
    unsafe {
        libc::fcntl(master_fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    let path = slave_path(master_fd).inspect_err(|_| unsafe {
        libc::close(master_fd);
    })?;
    let slave = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(&path)
    {
        Ok(f) => f,
        Err(err) => {
            unsafe { libc::close(master_fd) };
            return Err(err);
        }
    };
    copy_winsize(master_fd);
    let master = unsafe { File::from_raw_fd(master_fd) };
    Ok(Pty { master, slave })
}

fn slave_path(master_fd: RawFd) -> io::Result<PathBuf> {
    let _g = PTSNAME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ptr = unsafe { libc::ptsname(master_fd) };
    if ptr.is_null() {
        return Err(io::Error::last_os_error());
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
    Ok(PathBuf::from(cstr.to_string_lossy().as_ref()))
}

fn copy_winsize(master_fd: RawFd) {
    unsafe {
        if libc::isatty(1) != 1 {
            return;
        }
        let mut ws = std::mem::zeroed::<libc::winsize>();
        if libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) == 0 {
            let _ = libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws);
        }
    }
}

pub(super) fn attach_pty(cmd: &mut Command, slave: File) -> io::Result<()> {
    silence_echo_if_piped(&slave);
    let stdin = slave.try_clone()?;
    let stdout = slave.try_clone()?;
    cmd.stdin(Stdio::from(stdin));
    cmd.stdout(Stdio::from(stdout));
    cmd.stderr(Stdio::from(slave));
    unsafe {
        cmd.pre_exec(|| {
            // Userns after a controlling TTY can SIGTTIN/SIGTTOU-stop
            // the child; parent wait() then never returns.
            let _ = libc::signal(libc::SIGTTIN, libc::SIG_IGN);
            let _ = libc::signal(libc::SIGTTOU, libc::SIG_IGN);
            let _ = libc::signal(libc::SIGTSTP, libc::SIG_IGN);
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            let _ = libc::ioctl(0, libc::TIOCSCTTY as _, std::ptr::null::<libc::c_void>());
            Ok(())
        });
    }
    Ok(())
}

pub(super) fn pump_master(master: File) -> io::Result<(std::thread::JoinHandle<()>, File)> {
    let writer = master.try_clone()?;
    let out = super::copy_pipe(master, std::io::stdout());
    Ok((out, writer))
}

/// Piped parent stdin is not a TTY. Keep ICANON so VEOF still works;
/// drop ECHO so `printf hi | workpen run --tty -- cat` is not doubled.
fn silence_echo_if_piped(slave: &File) {
    if unsafe { libc::isatty(0) } == 1 {
        return;
    }
    unsafe {
        let fd = slave.as_raw_fd();
        let mut ios = std::mem::zeroed::<libc::termios>();
        if libc::tcgetattr(fd, &mut ios) != 0 {
            return;
        }
        ios.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
        let _ = libc::tcsetattr(fd, libc::TCSANOW, &ios);
    }
}

/// Copy parent stdin to the master. Closing the write clone does not
/// EOF the slave while the parent still reads the master, so write
/// VEOF (`\x04`) when host stdin ends.
pub(super) fn pump_stdin(mut master: File) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 16 * 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    let _ = master.write_all(&[4]);
                    break;
                }
                Ok(n) => {
                    if master.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
}
