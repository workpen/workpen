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
    #[cfg(windows)]
    if rest.first().is_some_and(|arg| arg == "--sec-probe") {
        return sec_probe(rest.get(1));
    }
    #[cfg(windows)]
    if rest.first().is_some_and(|arg| arg == "--hold-sid") {
        return hold_sid(rest.get(1));
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

/// `CreateFileMappingW` under this process token. `cat` passes
/// `sec_none`: a `SECURITY_ATTRIBUTES` whose descriptor pointer is null.
#[cfg(windows)]
fn sec_probe(sid_name: Option<&OsString>) -> ExitCode {
    let pid = std::process::id();
    map_shape("null-psa", &format!("wp-null-psa-{pid}"), 0, 4096);
    map_shape("sec-none", &format!("wp-sec-none-{pid}"), 1, 4096);
    map_shape("sec-all", &format!("wp-sec-all-{pid}"), 2, 4096);
    map_shape("null-psa-64m", &format!("wp-null-64m-{pid}"), 0, 64 * 1024 * 1024);
    let _ = sid_name;
    ExitCode::from(0)
}

/// Keep `NAME` mapped with `sec_none` until stdin closes. `cat` then
/// opens this section instead of creating a new one.
#[cfg(windows)]
fn hold_sid(name: Option<&OsString>) -> ExitCode {
    use std::io::{Read, Write};

    let Some(name) = name else {
        eprintln!("workpen-net-helper: missing sid name");
        return ExitCode::from(2);
    };
    let text = name.to_string_lossy();
    let mut held = Vec::new();
    for candidate in [
        text.to_string(),
        format!("Local\\{text}"),
        format!("Global\\{text}"),
        format!("Local\\Restricted\\{text}"),
    ] {
        let handle = map_open(&candidate, 1, 64 * 1024 * 1024);
        let err = unsafe { GetLastError() };
        let path = object_name(handle);
        eprintln!(
            "workpen-net-helper: sid-hold name={candidate} null={} err={err} path={path}",
            handle.is_null()
        );
        if !handle.is_null() {
            let dacl = grant_held_mapping(handle);
            eprintln!("workpen-net-helper: sid-dacl name={candidate} {dacl}");
            held.push(handle);
        }
    }
    if held.is_empty() {
        return ExitCode::from(1);
    }
    let mut out = std::io::stdout();
    let _ = writeln!(out, "READY");
    let _ = out.flush();
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
    for handle in held {
        unsafe { CloseHandle(handle) };
    }
    ExitCode::from(0)
}

#[cfg(windows)]
fn map_shape(label: &str, name: &str, mode: u8, size: u32) {
    let handle = map_open(name, mode, size);
    let err = unsafe { GetLastError() };
    eprintln!(
        "workpen-net-helper: shape={label} size={size} null={} err={err}",
        handle.is_null()
    );
    if !handle.is_null() {
        unsafe { CloseHandle(handle) };
    }
}

#[cfg(windows)]
fn map_open(name: &str, mode: u8, size: u32) -> *mut core::ffi::c_void {
    use std::os::windows::ffi::OsStrExt;

    let mut wide: Vec<u16> = std::ffi::OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut words = [0u64; 8];
    let sd = words.as_mut_ptr().cast::<u8>();
    if mode == 2 {
        let ready = unsafe {
            InitializeSecurityDescriptor(sd, 1) != 0
                && SetSecurityDescriptorDacl(sd, 1, std::ptr::null_mut(), 0) != 0
        };
        if !ready {
            return std::ptr::null_mut();
        }
    }
    let mut sa = SecurityAttributesHold {
        n_length: std::mem::size_of::<SecurityAttributesHold>() as u32,
        lp_security_descriptor: if mode == 2 {
            sd.cast()
        } else {
            std::ptr::null_mut()
        },
        b_inherit_handle: 1,
    };
    let attrs = if mode == 0 {
        std::ptr::null_mut()
    } else {
        &mut sa
    };
    unsafe {
        CreateFileMappingW(
            -1isize as *mut core::ffi::c_void,
            attrs,
            0x04,
            0,
            size,
            wide.as_mut_ptr(),
        )
    }
}

#[cfg(windows)]
fn grant_held_mapping(handle: *mut core::ffi::c_void) -> String {
    let mut nt = SidAuthority { value: [0, 0, 0, 0, 0, 5] };
    let mut world_auth = SidAuthority { value: [0, 0, 0, 0, 0, 1] };
    let mut restricted = std::ptr::null_mut();
    let mut world = std::ptr::null_mut();
    let restricted_ok = unsafe {
        AllocateAndInitializeSid(
            &mut nt, 1, 12, 0, 0, 0, 0, 0, 0, 0, &mut restricted,
        )
    };
    let world_ok = unsafe {
        AllocateAndInitializeSid(
            &mut world_auth, 1, 0, 0, 0, 0, 0, 0, 0, 0, &mut world,
        )
    };
    if restricted_ok == 0 || world_ok == 0 {
        return format!("sid={}", unsafe { GetLastError() });
    }
    let mut acl_words = vec![0u32; 64];
    let acl = acl_words.as_mut_ptr().cast::<u8>();
    let ready = unsafe {
        InitializeAcl(acl, (acl_words.len() * 4) as u32, 2) != 0
            && AddAccessAllowedAce(acl, 2, 0x1000_0000, world) != 0
            && AddAccessAllowedAce(acl, 2, 0x1000_0000, restricted) != 0
    };
    let result = if !ready {
        format!("acl={}", unsafe { GetLastError() })
    } else {
        let set = unsafe {
            SetSecurityInfo(
                handle,
                6,
                4,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if set == 0 {
            "ok".to_string()
        } else {
            format!("set={set}")
        }
    };
    unsafe {
        FreeSid(restricted);
        FreeSid(world);
    }
    result
}

#[cfg(windows)]
fn object_name(handle: *mut core::ffi::c_void) -> String {
    if handle.is_null() {
        return String::new();
    }
    let mut bytes = 0u32;
    unsafe { NtQueryObject(handle, 1, std::ptr::null_mut(), 0, &mut bytes) };
    if bytes < 16 || bytes > 4096 {
        return String::new();
    }
    let mut buf = vec![0u8; bytes as usize];
    let status = unsafe { NtQueryObject(handle, 1, buf.as_mut_ptr(), bytes, &mut bytes) };
    if status < 0 || buf.len() < 16 {
        return format!("status={status:#x}");
    }
    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize / 2;
    let ptr_val = usize::from_le_bytes(buf[8..16].try_into().unwrap_or([0; 8]));
    let start = buf.as_ptr() as usize;
    if ptr_val < start || len == 0 || ptr_val + len * 2 > start + buf.len() {
        return String::new();
    }
    let chars = unsafe { std::slice::from_raw_parts(ptr_val as *const u16, len) };
    String::from_utf16_lossy(chars)
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
    let null_sd = unsafe {
        CreateFileMappingW(
            -1isize as *mut core::ffi::c_void,
            std::ptr::null_mut(),
            0x04,
            0,
            16 * 1024 * 1024,
            wide.as_mut_ptr(),
        )
    };
    let null_err = unsafe { GetLastError() };
    eprintln!(
        "workpen-net-helper: null-sd null={} err={null_err}",
        null_sd.is_null()
    );
    if !null_sd.is_null() {
        unsafe { CloseHandle(null_sd) };
    }
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
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryObject(
        handle: *mut core::ffi::c_void,
        info_class: u32,
        buffer: *mut u8,
        length: u32,
        return_length: *mut u32,
    ) -> i32;
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
    fn AllocateAndInitializeSid(
        authority: *mut SidAuthority,
        sub_count: u8,
        sub0: u32,
        sub1: u32,
        sub2: u32,
        sub3: u32,
        sub4: u32,
        sub5: u32,
        sub6: u32,
        sub7: u32,
        sid: *mut *mut core::ffi::c_void,
    ) -> i32;
    fn FreeSid(sid: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    fn InitializeAcl(acl: *mut u8, length: u32, revision: u32) -> i32;
    fn AddAccessAllowedAce(acl: *mut u8, revision: u32, mask: u32, sid: *mut core::ffi::c_void)
        -> i32;
    fn SetSecurityInfo(
        handle: *mut core::ffi::c_void,
        object_type: u32,
        security_info: u32,
        owner: *mut core::ffi::c_void,
        group: *mut core::ffi::c_void,
        dacl: *mut u8,
        sacl: *mut core::ffi::c_void,
    ) -> u32;
}

#[cfg(windows)]
#[repr(C)]
struct SidAuthority {
    value: [u8; 6],
}

#[cfg(windows)]
#[repr(C)]
struct SecurityAttributesHold {
    n_length: u32,
    lp_security_descriptor: *mut core::ffi::c_void,
    b_inherit_handle: i32,
}
