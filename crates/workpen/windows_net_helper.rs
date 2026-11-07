//! Unique-PE wrap helper for Windows network deny. Compiled by build.rs only.

use std::env;
use std::ffi::OsString;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _argv0 = args.next();
    let rest: Vec<OsString> = args.collect();
    #[cfg(windows)]
    if rest.first().is_some_and(|arg| arg == "--hold-map") {
        return hold_map(rest.get(1));
    }
    let Some(dash) = rest.iter().position(|a| a == "--") else {
        eprintln!("workpen-net-helper: missing --");
        return ExitCode::from(2);
    };
    let cmd = &rest[dash + 1..];
    if cmd.is_empty() {
        eprintln!("workpen-net-helper: empty command");
        return ExitCode::from(2);
    }
    let mut child = Command::new(&cmd[0]);
    if cmd.len() > 1 {
        child.args(&cmd[1..]);
    }
    match child.status() {
        Ok(st) => std::process::exit(st.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("workpen-net-helper: spawn {}: {e}", cmd[0].to_string_lossy());
            ExitCode::from(1)
        }
    }
}

/// Create `NAME` with a null DACL in this process's Win32 namespace and
/// wait. The caller is the restricted token, so the mapping is where
/// `cat` will look. Closing stdin ends the wait.
#[cfg(windows)]
fn hold_map(name: Option<&OsString>) -> ExitCode {
    use std::io::{Read, Write};
    use std::os::windows::ffi::OsStrExt;

    let Some(name) = name else {
        eprintln!("workpen-net-helper: missing map name");
        return ExitCode::from(2);
    };
    let mut wide: Vec<u16> = name.encode_wide().chain(std::iter::once(0)).collect();
    let mut sd = [0u64; 8];
    let sd_ptr = sd.as_mut_ptr().cast::<u8>();
    let ready = unsafe {
        InitializeSecurityDescriptor(sd_ptr, 1) != 0
            && SetSecurityDescriptorDacl(sd_ptr, 1, std::ptr::null_mut(), 0) != 0
    };
    if !ready {
        eprintln!("workpen-net-helper: security descriptor failed");
        return ExitCode::from(1);
    }
    let mut sa = SecurityAttributesHold {
        n_length: std::mem::size_of::<SecurityAttributesHold>() as u32,
        lp_security_descriptor: sd_ptr.cast(),
        b_inherit_handle: 0,
    };
    let handle = unsafe {
        CreateFileMappingW(
            -1isize as *mut core::ffi::c_void,
            &mut sa,
            0x04,
            0,
            16 * 1024 * 1024,
            wide.as_mut_ptr(),
        )
    };
    if handle.is_null() {
        eprintln!(
            "workpen-net-helper: CreateFileMapping {}",
            unsafe { GetLastError() }
        );
        return ExitCode::from(1);
    }
    let mut out = std::io::stdout();
    let _ = writeln!(out, "ok");
    let _ = out.flush();
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
    unsafe { CloseHandle(handle) };
    ExitCode::from(0)
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileMappingW(
        h_file: *mut core::ffi::c_void,
        attrs: *mut SecurityAttributesHold,
        protect: u32,
        size_high: u32,
        size_low: u32,
        name: *mut u16,
    ) -> *mut core::ffi::c_void;
    fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
    fn GetLastError() -> u32;
}

#[cfg(windows)]
#[link(name = "advapi32")]
unsafe extern "system" {
    fn InitializeSecurityDescriptor(sd: *mut u8, revision: u32) -> i32;
    fn SetSecurityDescriptorDacl(
        sd: *mut u8,
        present: i32,
        dacl: *mut u8,
        defaulted: i32,
    ) -> i32;
}

#[cfg(windows)]
#[repr(C)]
struct SecurityAttributesHold {
    n_length: u32,
    lp_security_descriptor: *mut core::ffi::c_void,
    b_inherit_handle: i32,
}
