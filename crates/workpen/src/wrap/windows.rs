//! Write-restricted token spawn. Not a dest-parent-copy of Bline.

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use super::{KernelAccess, KernelApply, KernelError, KernelPolicy, combine_spawn_restore};

#[path = "windows_net.rs"]
mod windows_net;

type Handle = *mut core::ffi::c_void;
type Dword = u32;
type Bool = i32;

const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
const DISABLE_MAX_PRIVILEGE: Dword = 0x1;
const WRITE_RESTRICTED: Dword = 0x8;
const TOKEN_ASSIGN_PRIMARY: Dword = 0x0001;
const TOKEN_DUPLICATE: Dword = 0x0002;
const TOKEN_QUERY: Dword = 0x0008;
const TOKEN_ADJUST_DEFAULT: Dword = 0x0080;
const TOKEN_ADJUST_SESSIONID: Dword = 0x0100;
const TOKEN_PRIMARY_MASK: Dword = TOKEN_ASSIGN_PRIMARY
    | TOKEN_DUPLICATE
    | TOKEN_QUERY
    | TOKEN_ADJUST_DEFAULT
    | TOKEN_ADJUST_SESSIONID;
const SECURITY_NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];
const SECURITY_WORLD_SID_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 1];
const SECURITY_RESTRICTED_CODE_RID: Dword = 12;
const SECURITY_WORLD_RID: Dword = 0;
const GENERIC_ALL: Dword = 0x1000_0000;
const GRANT_ACCESS: u32 = 1;
const DENY_ACCESS: u32 = 3;
const NO_INHERITANCE: Dword = 0;
const TRUSTEE_IS_SID: u32 = 0;
const TRUSTEE_IS_WELL_KNOWN_GROUP: u32 = 5;
const NO_MULTIPLE_TRUSTEE: u32 = 0;
const SUB_CONTAINERS_AND_OBJECTS_INHERIT: Dword = 0x3;
const SE_FILE_OBJECT: u32 = 1;
const DACL_SECURITY_INFORMATION: Dword = 0x4;
const CREATE_SUSPENDED: Dword = 0x0000_0004;
const CREATE_UNICODE_ENVIRONMENT: Dword = 0x0000_0400;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Dword = 0x2000;
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: u32 = 9;
const TOKEN_PRIMARY: u32 = 1;
const SECURITY_IMPERSONATION: u32 = 2;
const INFINITE: Dword = 0xFFFF_FFFF;
const WAIT_OBJECT_0: Dword = 0;
const WAIT_TIMEOUT: Dword = 0x0000_0102;
const WAIT_FAILED: Dword = 0xFFFF_FFFF;
const STD_INPUT_HANDLE: Dword = -10i32 as Dword;
const STD_OUTPUT_HANDLE: Dword = -11i32 as Dword;
const STD_ERROR_HANDLE: Dword = -12i32 as Dword;
const STARTF_USESTDHANDLES: Dword = 0x0000_0100;
const DUPLICATE_SAME_ACCESS: Dword = 0x0000_0002;
const GENERIC_READ: Dword = 0x8000_0000;
const GENERIC_WRITE: Dword = 0x4000_0000;
const GENERIC_EXECUTE: Dword = 0x2000_0000;
const SE_KERNEL_OBJECT: u32 = 6;
const JOB_OBJECT_BASIC_UI_RESTRICTIONS: u32 = 4;
const JOB_OBJECT_UILIMIT_HANDLES: Dword = 0x0000_0001;
const JOB_OBJECT_UILIMIT_READCLIPBOARD: Dword = 0x0000_0002;
const JOB_OBJECT_UILIMIT_WRITECLIPBOARD: Dword = 0x0000_0004;
const JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS: Dword = 0x0000_0008;
const JOB_OBJECT_UILIMIT_EXITWINDOWS: Dword = 0x0000_0080;
/// Clipboard, system parameters, and ExitWindows. Not HANDLES:
/// that flag blocks USER handles owned outside the job, including
/// the parent console, and MSYS `DllMain` then exits `0xC0000142`.
const UI_RESTRICTIONS: Dword = JOB_OBJECT_UILIMIT_READCLIPBOARD
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_EXITWINDOWS;
const _: () = assert!(UI_RESTRICTIONS & JOB_OBJECT_UILIMIT_HANDLES == 0);
const FILE_SHARE_READ: Dword = 0x0001;
const FILE_SHARE_WRITE: Dword = 0x0002;
const OPEN_EXISTING: Dword = 3;

#[repr(C)]
struct SidIdentifierAuthority {
    value: [u8; 6],
}

#[repr(C)]
struct SidAndAttributes {
    sid: Handle,
    attributes: Dword,
}

#[repr(C)]
struct Luid {
    low_part: Dword,
    high_part: i32,
}

#[repr(C)]
#[cfg_attr(not(test), allow(dead_code))]
struct LuidAndAttributes {
    luid: Luid,
    attributes: Dword,
}

#[repr(C)]
struct TrusteeW {
    p_multiple_trustee: *mut TrusteeW,
    multiple_trustee_operation: u32,
    trustee_form: u32,
    trustee_type: u32,
    ptstr_name: Handle,
}

#[repr(C)]
struct ExplicitAccessW {
    grf_access_permissions: Dword,
    grf_access_mode: u32,
    grf_inheritance: Dword,
    trustee: TrusteeW,
}

#[repr(C)]
struct StartupInfoW {
    cb: Dword,
    lp_reserved: *mut u16,
    lp_desktop: *mut u16,
    lp_title: *mut u16,
    dw_x: Dword,
    dw_y: Dword,
    dw_x_size: Dword,
    dw_y_size: Dword,
    dw_x_count_chars: Dword,
    dw_y_count_chars: Dword,
    dw_fill_attribute: Dword,
    dw_flags: Dword,
    w_show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: *mut u8,
    h_std_input: Handle,
    h_std_output: Handle,
    h_std_error: Handle,
}

#[repr(C)]
struct ProcessInformation {
    h_process: Handle,
    h_thread: Handle,
    dw_process_id: Dword,
    dw_thread_id: Dword,
}

#[repr(C)]
struct SecurityAttributes {
    n_length: Dword,
    lp_security_descriptor: *mut core::ffi::c_void,
    b_inherit_handle: Bool,
}

#[repr(C)]
struct JobobjectBasicLimitInformation {
    per_process_user_time_limit: i64,
    per_job_user_time_limit: i64,
    limit_flags: Dword,
    minimum_working_set_size: usize,
    maximum_working_set_size: usize,
    active_process_limit: Dword,
    affinity: usize,
    priority_class: Dword,
    scheduling_class: Dword,
}

#[repr(C)]
struct IoCounters {
    read_operation_count: u64,
    write_operation_count: u64,
    other_operation_count: u64,
    read_transfer_count: u64,
    write_transfer_count: u64,
    other_transfer_count: u64,
}

#[repr(C)]
struct JobobjectExtendedLimitInformation {
    basic_limit_information: JobobjectBasicLimitInformation,
    io_info: IoCounters,
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentProcessId() -> Dword;
    fn ProcessIdToSessionId(dw_process_id: Dword, p_session_id: *mut Dword) -> Bool;
    fn GetCurrentThread() -> Handle;
    fn CancelSynchronousIo(h_thread: Handle) -> Bool;
    fn CloseHandle(h_object: Handle) -> Bool;
    fn GetLastError() -> Dword;
    fn SearchPathW(
        lp_path: *const u16,
        lp_file_name: *const u16,
        lp_extension: *const u16,
        n_buffer_length: Dword,
        lp_buffer: *mut u16,
        lp_file_part: *mut *mut u16,
    ) -> Dword;
    fn CreateJobObjectW(lp_job_attributes: *mut core::ffi::c_void, lp_name: *const u16) -> Handle;
    fn SetInformationJobObject(
        h_job: Handle,
        job_object_information_class: u32,
        lp_job_object_information: *mut core::ffi::c_void,
        cb_job_object_information_length: Dword,
    ) -> Bool;
    fn AssignProcessToJobObject(h_job: Handle, h_process: Handle) -> Bool;
    fn ResumeThread(h_thread: Handle) -> Dword;
    fn WaitForSingleObject(h_handle: Handle, dw_milliseconds: Dword) -> Dword;
    fn GetExitCodeProcess(h_process: Handle, lp_exit_code: *mut Dword) -> Bool;
    fn TerminateProcess(h_process: Handle, u_exit_code: u32) -> Bool;
    fn GetStdHandle(n_std_handle: Dword) -> Handle;
    fn DuplicateHandle(
        h_source_process_handle: Handle,
        h_source_handle: Handle,
        h_target_process_handle: Handle,
        lp_target_handle: *mut Handle,
        dw_desired_access: Dword,
        b_inherit_handle: Bool,
        dw_options: Dword,
    ) -> Bool;
    fn CreateFileW(
        lp_file_name: *const u16,
        dw_desired_access: Dword,
        dw_share_mode: Dword,
        lp_security_attributes: *mut core::ffi::c_void,
        dw_creation_disposition: Dword,
        dw_flags_and_attributes: Dword,
        h_template_file: Handle,
    ) -> Handle;
    fn GetModuleHandleW(lp_module_name: *const u16) -> Handle;
    fn GetProcAddress(h_module: Handle, lp_proc_name: *const u8) -> *mut core::ffi::c_void;
    fn CreatePipe(
        h_read_pipe: *mut Handle,
        h_write_pipe: *mut Handle,
        lp_pipe_attributes: *mut SecurityAttributes,
        n_size: Dword,
    ) -> Bool;
    fn ReadFile(
        h_file: Handle,
        lp_buffer: *mut u8,
        n_number_of_bytes_to_read: Dword,
        lp_number_of_bytes_read: *mut Dword,
        lp_overlapped: *mut core::ffi::c_void,
    ) -> Bool;
    fn WriteFile(
        h_file: Handle,
        lp_buffer: *const u8,
        n_number_of_bytes_to_write: Dword,
        lp_number_of_bytes_written: *mut Dword,
        lp_overlapped: *mut core::ffi::c_void,
    ) -> Bool;
    fn SetHandleInformation(h_object: Handle, dw_mask: Dword, dw_flags: Dword) -> Bool;
}

const HANDLE_FLAG_INHERIT: Dword = 0x0000_0001;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(
        process_handle: Handle,
        desired_access: Dword,
        token_handle: *mut Handle,
    ) -> Bool;
    fn CreateRestrictedToken(
        existing_token_handle: Handle,
        flags: Dword,
        disable_sid_count: Dword,
        sids_to_disable: *const SidAndAttributes,
        delete_privilege_count: Dword,
        privileges_to_delete: *const core::ffi::c_void,
        restricted_sid_count: Dword,
        sids_to_restrict: *const SidAndAttributes,
        new_token_handle: *mut Handle,
    ) -> Bool;
    fn DuplicateTokenEx(
        h_existing_token: Handle,
        dw_desired_access: Dword,
        lp_token_attributes: *mut core::ffi::c_void,
        impersonation_level: u32,
        token_type: u32,
        ph_new_token: *mut Handle,
    ) -> Bool;
    fn CreateProcessAsUserW(
        h_token: Handle,
        lp_application_name: *const u16,
        lp_command_line: *mut u16,
        lp_process_attributes: *mut core::ffi::c_void,
        lp_thread_attributes: *mut core::ffi::c_void,
        b_inherit_handles: Bool,
        dw_creation_flags: Dword,
        lp_environment: *mut core::ffi::c_void,
        lp_current_directory: *const u16,
        lp_startup_info: *mut StartupInfoW,
        lp_process_information: *mut ProcessInformation,
    ) -> Bool;
    fn AllocateAndInitializeSid(
        p_identifier_authority: *const SidIdentifierAuthority,
        n_sub_authority_count: u8,
        n_sub_authority0: Dword,
        n_sub_authority1: Dword,
        n_sub_authority2: Dword,
        n_sub_authority3: Dword,
        n_sub_authority4: Dword,
        n_sub_authority5: Dword,
        n_sub_authority6: Dword,
        n_sub_authority7: Dword,
        p_sid: *mut Handle,
    ) -> Bool;
    fn FreeSid(p_sid: Handle) -> Handle;
    fn GetNamedSecurityInfoW(
        p_object_name: *const u16,
        object_type: u32,
        security_info: Dword,
        ppsid_owner: *mut Handle,
        ppsid_group: *mut Handle,
        pp_dacl: *mut Handle,
        pp_sacl: *mut Handle,
        pp_security_descriptor: *mut Handle,
    ) -> Dword;
    fn SetNamedSecurityInfoW(
        p_object_name: *mut u16,
        object_type: u32,
        security_info: Dword,
        psid_owner: Handle,
        psid_group: Handle,
        p_dacl: Handle,
        p_sacl: Handle,
    ) -> Dword;
    fn SetEntriesInAclW(
        c_count_of_explicit_entries: u32,
        p_list_of_explicit_entries: *mut ExplicitAccessW,
        old_acl: Handle,
        new_acl: *mut Handle,
    ) -> Dword;
    fn GetTokenInformation(
        token_handle: Handle,
        token_information_class: u32,
        token_information: *mut core::ffi::c_void,
        token_information_length: Dword,
        return_length: *mut Dword,
    ) -> Bool;
    fn SetTokenInformation(
        token_handle: Handle,
        token_information_class: u32,
        token_information: *mut core::ffi::c_void,
        token_information_length: Dword,
    ) -> Bool;
    #[cfg_attr(not(test), allow(dead_code))]
    fn LookupPrivilegeValueW(
        lp_system_name: *const u16,
        lp_name: *const u16,
        lp_luid: *mut Luid,
    ) -> Bool;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(h_mem: Handle) -> Handle;
}

struct CloseOnDrop(Handle);
// SAFETY: exclusive kernel HANDLE; drain threads take ownership.
unsafe impl Send for CloseOnDrop {}
impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: `self.0` is a kernel handle we own.
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = ptr::null_mut();
        }
    }
}

struct RestrictedSid(Handle);
impl RestrictedSid {
    fn new() -> Result<Self, KernelError> {
        let authority = SidIdentifierAuthority {
            value: SECURITY_NT_AUTHORITY,
        };
        let mut sid = ptr::null_mut();
        // SAFETY: `authority` lives for the call; `sid` is written by the API.
        let ok = unsafe {
            AllocateAndInitializeSid(
                &authority,
                1,
                SECURITY_RESTRICTED_CODE_RID,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut sid,
            )
        };
        if ok == 0 || sid.is_null() {
            return Err(last_error("AllocateAndInitializeSid"));
        }
        Ok(Self(sid))
    }
}
impl Drop for RestrictedSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` came from AllocateAndInitializeSid.
            unsafe {
                FreeSid(self.0);
            }
            self.0 = ptr::null_mut();
        }
    }
}

struct WorldSid(Handle);
impl WorldSid {
    fn new() -> Result<Self, KernelError> {
        let authority = SidIdentifierAuthority {
            value: SECURITY_WORLD_SID_AUTHORITY,
        };
        let mut sid = ptr::null_mut();
        // SAFETY: `authority` lives for the call; `sid` is written by the API.
        let ok = unsafe {
            AllocateAndInitializeSid(
                &authority,
                1,
                SECURITY_WORLD_RID,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut sid,
            )
        };
        if ok == 0 || sid.is_null() {
            return Err(last_error("AllocateAndInitializeSid"));
        }
        Ok(Self(sid))
    }
}
impl Drop for WorldSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` came from AllocateAndInitializeSid.
            unsafe {
                FreeSid(self.0);
            }
            self.0 = ptr::null_mut();
        }
    }
}

struct LocalMem(Handle);
impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` came from LocalAlloc / GetNamedSecurityInfo / SetEntriesInAcl.
            unsafe {
                LocalFree(self.0);
            }
            self.0 = ptr::null_mut();
        }
    }
}

struct AclRestore {
    path: Vec<u16>,
    object_type: u32,
    /// Owns the security descriptor so `dacl` stays valid until restore.
    _sd: LocalMem,
    dacl: Handle,
    restored: bool,
}
impl AclRestore {
    fn restore(&mut self) -> Result<(), KernelError> {
        if self.restored {
            return Ok(());
        }
        // SAFETY: `path` is a NUL-terminated object name; `dacl` is from the saved SD.
        let err = unsafe {
            SetNamedSecurityInfoW(
                self.path.as_mut_ptr(),
                self.object_type,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                self.dacl,
                ptr::null_mut(),
            )
        };
        if err != 0 {
            return Err(win32_error("restore DACL", err));
        }
        self.restored = true;
        Ok(())
    }
}
impl Drop for AclRestore {
    fn drop(&mut self) {
        if let Err(err) = self.restore() {
            eprintln!("workpen: {err}");
        }
    }
}

// Propagate restore errors. Drop only eprintln-swallows leftovers.
fn restore_guards(guards: &mut [AclRestore]) -> Result<(), KernelError> {
    // Later ACEs saved the DACL that already included earlier ACEs.
    // Restore the last write first so the original DACL is what remains.
    for guard in guards.iter_mut().rev() {
        guard.restore()?;
    }
    Ok(())
}

pub(super) unsafe fn free_sid(sid: Handle) {
    // SAFETY: caller owns a SID from AllocateAndInitializeSid or userenv.
    unsafe {
        FreeSid(sid);
    }
}

fn last_error(op: &str) -> KernelError {
    // SAFETY: GetLastError has no preconditions.
    let err = unsafe { GetLastError() };
    KernelError::Apply(format!("{op} failed (win32 {err})"))
}

fn win32_error(op: &str, err: Dword) -> KernelError {
    KernelError::Apply(format!("{op} failed (win32 {err})"))
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn wide_os(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

pub(super) fn write_restricted_supported() -> bool {
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(probe_write_restricted)
}

fn probe_write_restricted() -> bool {
    let Ok(sid) = RestrictedSid::new() else {
        return false;
    };
    create_write_restricted_token(sid.0).is_ok()
}

struct Prepared {
    token: CloseOnDrop,
    job: CloseOnDrop,
    acl_guards: Vec<AclRestore>,
    _sid: RestrictedSid,
    _world: WorldSid,
    helper: Option<PathBuf>,
    _net: Option<NetGuards>,
    wfp_skipped: bool,
}

struct NetGuards {
    _helper: windows_net::HelperFile,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StdioCapture {
    Inherit,
    Collect,
    Forward,
}

pub(super) fn spawn_write_restricted(
    policy: &KernelPolicy,
    cmd: &mut Command,
    timeout: Option<Duration>,
) -> Result<(KernelApply, ExitStatus), KernelError> {
    let (applied, status, _, timed_out) =
        spawn_write_restricted_io(policy, cmd, timeout, StdioCapture::Inherit)?;
    if timed_out {
        return Err(KernelError::Timeout);
    }
    Ok((applied, status))
}

pub(super) fn spawn_write_restricted_output(
    policy: &KernelPolicy,
    cmd: &mut Command,
    timeout: Option<Duration>,
) -> Result<(KernelApply, std::process::Output, bool), KernelError> {
    let (applied, status, output, timed_out) =
        spawn_write_restricted_io(policy, cmd, timeout, StdioCapture::Collect)?;
    Ok((
        applied,
        output.unwrap_or_else(|| std::process::Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }),
        timed_out,
    ))
}

pub(super) fn spawn_reexec(
    policy: &KernelPolicy,
    cmd: &mut Command,
    timeout: Option<Duration>,
) -> Result<(KernelApply, ExitStatus), KernelError> {
    let (applied, status, _, timed_out) =
        spawn_reexec_io(policy, cmd, timeout, StdioCapture::Inherit)?;
    if timed_out {
        return Err(KernelError::Timeout);
    }
    Ok((applied, status))
}

pub(super) fn spawn_reexec_output(
    policy: &KernelPolicy,
    cmd: &mut Command,
    timeout: Option<Duration>,
) -> Result<(KernelApply, std::process::Output, bool), KernelError> {
    let (applied, status, output, timed_out) =
        spawn_reexec_io(policy, cmd, timeout, StdioCapture::Collect)?;
    Ok((
        applied,
        output.unwrap_or_else(|| std::process::Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }),
        timed_out,
    ))
}

fn spawn_reexec_io(
    policy: &KernelPolicy,
    cmd: &mut Command,
    timeout: Option<Duration>,
    capture: StdioCapture,
) -> Result<(KernelApply, ExitStatus, Option<std::process::Output>, bool), KernelError> {
    let prepared = prepare_contained(policy, windows_net::ContainerKind::Allowed)?;
    spawn_prepared(prepared, cmd, timeout, capture)
}

pub(super) fn shutdown_jail_cache() {
    windows_net::shutdown_cache();
}

pub(super) fn spawn_write_restricted_forward(
    policy: &KernelPolicy,
    cmd: &mut Command,
    timeout: Option<Duration>,
) -> Result<(KernelApply, ExitStatus, bool), KernelError> {
    let (applied, status, _, timed_out) =
        spawn_write_restricted_io(policy, cmd, timeout, StdioCapture::Forward)?;
    Ok((applied, status, timed_out))
}

fn spawn_write_restricted_io(
    policy: &KernelPolicy,
    cmd: &mut Command,
    timeout: Option<Duration>,
    capture: StdioCapture,
) -> Result<(KernelApply, ExitStatus, Option<std::process::Output>, bool), KernelError> {
    let prepared = if policy.network_blocked() {
        prepare_network_blocked(policy)?
    } else {
        prepare_write_restricted(policy)?
    };
    spawn_prepared(prepared, cmd, timeout, capture)
}

fn prepare_write_restricted(policy: &KernelPolicy) -> Result<Prepared, KernelError> {
    let sid = RestrictedSid::new()?;
    let world = WorldSid::new()?;
    let mut acl_guards = grant_write_aces(&rw_grant_paths(policy), sid.0)?;
    acl_guards.extend(deny_dest_aces(&dest_deny_paths(policy), world.0)?);
    acl_guards.extend(deny_dest_aces(&profile_secret_paths(), sid.0)?);
    acl_guards.extend(allow_session_object_create(sid.0)?);
    let token = create_write_restricted_token(sid.0).map_err(prefix_apply("token setup"))?;
    let job = create_kill_job().map_err(prefix_apply("job setup"))?;
    Ok(Prepared {
        token,
        job,
        acl_guards,
        _sid: sid,
        _world: world,
        helper: None,
        _net: None,
        wfp_skipped: false,
    })
}

fn prepare_network_blocked(policy: &KernelPolicy) -> Result<Prepared, KernelError> {
    prepare_contained(policy, windows_net::ContainerKind::Blocked)
}

fn prepare_contained(
    policy: &KernelPolicy,
    kind: windows_net::ContainerKind,
) -> Result<Prepared, KernelError> {
    let anchor = container_anchor(policy)?;
    let helper = windows_net::HelperFile::install(&anchor).map_err(prefix_apply("net helper"))?;
    let (package, wfp_skipped) =
        windows_net::acquire(kind, helper.path()).map_err(prefix_apply("AppContainer profile"))?;
    let package_sid = package.as_handle();
    let mut prepared = prepare_write_restricted(policy)?;
    for path in rw_grant_paths(policy) {
        grant_package_root(&path, package_sid, &mut prepared.acl_guards)?;
    }
    for path in read_grant_paths(policy) {
        grant_package_read(&path, package_sid, &mut prepared.acl_guards)?;
    }
    prepared
        .acl_guards
        .extend(deny_dest_aces(&dest_deny_paths(policy), package_sid)?);
    prepared
        .acl_guards
        .extend(deny_dest_aces(&profile_secret_paths(), package_sid)?);
    prepared.acl_guards.push(set_acl_entry(
        helper.path(),
        package_sid,
        GENERIC_ALL,
        GRANT_ACCESS,
        NO_INHERITANCE,
    )?);
    prepared.wfp_skipped = match kind {
        windows_net::ContainerKind::Blocked => wfp_skipped,
        windows_net::ContainerKind::Allowed => false,
    };
    prepared.token = wrap_appcontainer_token(prepared.token, package_sid)?;
    prepared.helper = Some(helper.path().to_path_buf());
    prepared._net = Some(NetGuards { _helper: helper });
    Ok(prepared)
}

fn container_anchor(policy: &KernelPolicy) -> Result<PathBuf, KernelError> {
    if let Some(path) = rw_grant_paths(policy).into_iter().next() {
        return Ok(path);
    }
    read_grant_paths(policy)
        .into_iter()
        .next()
        .ok_or_else(|| KernelError::Apply("container jail needs a read or read-write grant".into()))
}

/// `.ssh`, `.aws`, `.gnupg`, `.azure`, `.config\gh`, `.docker`, `.kube`
/// under `%USERPROFILE%`. Missing directories are skipped by
/// [`deny_dest_aces`]. This does not walk the profile.
fn profile_secret_paths() -> Vec<PathBuf> {
    let Some(root) = std::env::var_os("USERPROFILE") else {
        return Vec::new();
    };
    let root = PathBuf::from(root);
    [
        ".ssh",
        ".aws",
        ".gnupg",
        ".azure",
        r".config\gh",
        ".docker",
        ".kube",
    ]
    .into_iter()
    .map(|rel| root.join(rel))
    .collect()
}

/// Let the restricting SID create objects in the session namespace and
/// in `\BaseNamedObjects`. MSYS `DllMain` calls `NtCreateDirectoryObject`
/// on `\BaseNamedObjects\msys-*`. That needs
/// `DIRECTORY_CREATE_SUBDIRECTORY`, not only `DIRECTORY_CREATE_OBJECT`.
/// `0xC0000022` is that deny. The ACEs are restored with the other jail
/// ACLs. A failure here does not fail the spawn: System32 tools do not
/// need the section.
fn allow_session_object_create(sid: Handle) -> Result<Vec<AclRestore>, KernelError> {
    let rights = DIRECTORY_QUERY
        | DIRECTORY_TRAVERSE
        | DIRECTORY_CREATE_OBJECT
        | DIRECTORY_CREATE_SUBDIRECTORY;
    let mut guards = Vec::new();
    for path in object_namespace_dirs() {
        if let Ok(guard) = set_named_ace(
            &path,
            SE_KERNEL_OBJECT,
            sid,
            rights,
            GRANT_ACCESS,
            NO_INHERITANCE,
        ) {
            guards.push(guard);
        }
    }
    Ok(guards)
}

const DIRECTORY_QUERY: Dword = 0x0001;
const DIRECTORY_TRAVERSE: Dword = 0x0002;
const DIRECTORY_CREATE_OBJECT: Dword = 0x0004;
const DIRECTORY_CREATE_SUBDIRECTORY: Dword = 0x0008;

fn object_namespace_dirs() -> Vec<Vec<u16>> {
    let mut paths = vec![wide_os(OsStr::new(r"\BaseNamedObjects"))];
    if let Some(session) = session_object_dir() {
        paths.push(session);
    }
    paths
}

fn session_object_dir() -> Option<Vec<u16>> {
    let mut session = 0u32;
    // SAFETY: current process id is valid.
    let ok = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) };
    if ok == 0 {
        return None;
    }
    let path = format!("\\Sessions\\{session}\\BaseNamedObjects");
    Some(wide_os(OsStr::new(&path)))
}

/// AppContainer plus WFP on `workspace`, without creating a user process.
/// `Ok(true)` is win32 5 (WFP skipped). The helper file is removed on drop.
pub(super) fn probe_wfp_skipped(workspace: &Path) -> Result<bool, KernelError> {
    let policy = super::process_jail(workspace, std::iter::empty::<&Path>())?;
    let prepared = prepare_network_blocked(&policy)?;
    Ok(prepared.wfp_skipped)
}

fn wrap_appcontainer_token(
    restricted: CloseOnDrop,
    package_sid: Handle,
) -> Result<CloseOnDrop, KernelError> {
    match windows_net::create_appcontainer_token(restricted.0, package_sid) {
        Ok(handle) => {
            drop(restricted);
            Ok(CloseOnDrop(handle))
        }
        Err(first) => {
            let current = current_primary_token()?;
            match windows_net::create_appcontainer_token(current.0, package_sid) {
                Ok(handle) => {
                    drop((restricted, current));
                    Ok(CloseOnDrop(handle))
                }
                Err(second) => Err(KernelError::Apply(format!(
                    "AppContainer token failed ({first}); fallback ({second})"
                ))),
            }
        }
    }
}

fn current_primary_token() -> Result<CloseOnDrop, KernelError> {
    let process_token = open_current_process_token()?;
    duplicate_primary_token(process_token.0)
}

/// One inheritable GRANT on the ReadWrite root. Dest-deny files get an
/// explicit package DENY after this so inherit cannot reopen them.
fn grant_package_root(
    root: &Path,
    sid: Handle,
    guards: &mut Vec<AclRestore>,
) -> Result<(), KernelError> {
    let meta = std::fs::symlink_metadata(root)
        .map_err(|e| KernelError::Apply(format!("package ACE {}: {e}", root.display())))?;
    let is_dir = meta.is_dir() && !meta.file_type().is_symlink();
    let inherit = if is_dir {
        SUB_CONTAINERS_AND_OBJECTS_INHERIT
    } else {
        NO_INHERITANCE
    };
    guards.push(set_acl_entry(
        root,
        sid,
        GENERIC_ALL,
        GRANT_ACCESS,
        inherit,
    )?);
    Ok(())
}

/// Read and execute for a Read grant. Not `GENERIC_ALL`, so a read-only
/// root cannot be created in by the package SID.
fn grant_package_read(
    root: &Path,
    sid: Handle,
    guards: &mut Vec<AclRestore>,
) -> Result<(), KernelError> {
    let meta = std::fs::symlink_metadata(root)
        .map_err(|e| KernelError::Apply(format!("package read ACE {}: {e}", root.display())))?;
    let is_dir = meta.is_dir() && !meta.file_type().is_symlink();
    let inherit = if is_dir {
        SUB_CONTAINERS_AND_OBJECTS_INHERIT
    } else {
        NO_INHERITANCE
    };
    guards.push(set_acl_entry(
        root,
        sid,
        GENERIC_READ | GENERIC_EXECUTE,
        GRANT_ACCESS,
        inherit,
    )?);
    Ok(())
}

fn prefix_apply(kind: &'static str) -> impl FnOnce(KernelError) -> KernelError {
    move |err| match err {
        KernelError::Apply(msg) => KernelError::Apply(format!("{kind} failed: {msg}")),
        other => other,
    }
}

fn inheritable_std_handle(std_id: Dword, write: bool) -> Result<CloseOnDrop, KernelError> {
    // SAFETY: GetStdHandle is always valid to call.
    let parent = unsafe { GetStdHandle(std_id) };
    if !parent.is_null() && parent != INVALID_HANDLE_VALUE {
        let current = unsafe { GetCurrentProcess() };
        let mut dup = ptr::null_mut();
        // SAFETY: `current` is this process; `parent` is a live std handle.
        let ok = unsafe {
            DuplicateHandle(
                current,
                parent,
                current,
                &mut dup,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            return open_nul(write);
        }
        return Ok(CloseOnDrop(dup));
    }
    open_nul(write)
}

fn open_nul(write: bool) -> Result<CloseOnDrop, KernelError> {
    let name = wide_os(OsStr::new("NUL"));
    let mut sa = SecurityAttributes {
        n_length: std::mem::size_of::<SecurityAttributes>() as Dword,
        lp_security_descriptor: ptr::null_mut(),
        b_inherit_handle: 1,
    };
    let access = if write { GENERIC_WRITE } else { GENERIC_READ };
    // SAFETY: `name` is NUL-terminated; `sa` lives for the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            (&raw mut sa).cast(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(last_error("CreateFileW"));
    }
    Ok(CloseOnDrop(handle))
}

fn spawn_prepared(
    mut prepared: Prepared,
    cmd: &mut Command,
    timeout: Option<Duration>,
    capture: StdioCapture,
) -> Result<(KernelApply, ExitStatus, Option<std::process::Output>, bool), KernelError> {
    let result = spawn_prepared_child(&mut prepared, cmd, timeout, capture);
    let restore = restore_guards(&mut prepared.acl_guards);
    match (result, restore) {
        (Ok((applied, status, output, timed_out)), Ok(())) => {
            Ok((applied, status, output, timed_out))
        }
        // Deadline plus restore failure must stay Timeout (unit variant).
        (Ok((_, _, _, true)), restore) => combine_spawn_restore(Err(KernelError::Timeout), restore)
            .map(|(applied, status)| (applied, status, None, true)),
        (result, restore) => combine_spawn_restore(
            result.map(|(applied, status, _, _)| (applied, status)),
            restore,
        )
        .map(|(applied, status)| (applied, status, None, false)),
    }
}

fn spawn_prepared_child(
    prepared: &mut Prepared,
    cmd: &mut Command,
    timeout: Option<Duration>,
    capture: StdioCapture,
) -> Result<(KernelApply, ExitStatus, Option<std::process::Output>, bool), KernelError> {
    let (app, mut cmdline, cwd) = match prepared.helper.as_deref() {
        Some(helper) => wrap_command_line(helper, cmd)?,
        None => command_line(cmd)?,
    };
    let mut env_block = environment_block(cmd);
    let std_in = inheritable_std_handle(STD_INPUT_HANDLE, false)?;
    let piped = matches!(capture, StdioCapture::Collect | StdioCapture::Forward);
    let (std_out, stdout_read) = if piped {
        inheritable_pipe(true)?
    } else {
        (inheritable_std_handle(STD_OUTPUT_HANDLE, true)?, None)
    };
    let (std_err, stderr_read) = if piped {
        inheritable_pipe(true)?
    } else {
        (inheritable_std_handle(STD_ERROR_HANDLE, true)?, None)
    };
    let forward_dst = if capture == StdioCapture::Forward {
        Some((
            duplicate_std_handle(STD_OUTPUT_HANDLE, true)?,
            duplicate_std_handle(STD_ERROR_HANDLE, true)?,
        ))
    } else {
        None
    };
    let mut startup = StartupInfoW {
        cb: std::mem::size_of::<StartupInfoW>() as Dword,
        lp_reserved: ptr::null_mut(),
        lp_desktop: ptr::null_mut(),
        lp_title: ptr::null_mut(),
        dw_x: 0,
        dw_y: 0,
        dw_x_size: 0,
        dw_y_size: 0,
        dw_x_count_chars: 0,
        dw_y_count_chars: 0,
        dw_fill_attribute: 0,
        dw_flags: STARTF_USESTDHANDLES,
        w_show_window: 0,
        cb_reserved2: 0,
        lp_reserved2: ptr::null_mut(),
        h_std_input: std_in.0,
        h_std_output: std_out.0,
        h_std_error: std_err.0,
    };
    let mut info = ProcessInformation {
        h_process: ptr::null_mut(),
        h_thread: ptr::null_mut(),
        dw_process_id: 0,
        dw_thread_id: 0,
    };
    let cwd_ptr = cwd.as_ref().map_or(ptr::null(), |c| c.as_ptr());
    // SAFETY: token is a primary write-restricted token; buffers are NUL-terminated
    // and live for the call. cmdline is writable as CreateProcessAsUserW requires.
    let created = unsafe {
        CreateProcessAsUserW(
            prepared.token.0,
            app.as_ptr(),
            cmdline.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            1,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            env_block.as_mut_ptr().cast(),
            cwd_ptr,
            &mut startup,
            &mut info,
        )
    };
    if created == 0 {
        return Err(last_error("CreateProcessAsUserW"));
    }
    drop((std_in, std_out, std_err));
    let process = CloseOnDrop(info.h_process);
    let thread = CloseOnDrop(info.h_thread);
    // Drain capture pipes before the child runs so a large write cannot
    // fill the pipe and block WaitForSingleObject.
    let forward_stop = Arc::new(AtomicBool::new(false));
    let forward_threads = Arc::new(Mutex::new(Vec::<CloseOnDrop>::new()));
    let (stdout_drain, stderr_drain, stdout_fwd, stderr_fwd) = match (capture, forward_dst) {
        (StdioCapture::Collect, _) => (
            stdout_read.map(drain_pipe),
            stderr_read.map(drain_pipe),
            None,
            None,
        ),
        (StdioCapture::Forward, Some((parent_out, parent_err))) => (
            None,
            None,
            stdout_read.map(|h| {
                drain_forward(
                    h,
                    parent_out,
                    Arc::clone(&forward_stop),
                    Arc::clone(&forward_threads),
                )
            }),
            stderr_read.map(|h| {
                drain_forward(
                    h,
                    parent_err,
                    Arc::clone(&forward_stop),
                    Arc::clone(&forward_threads),
                )
            }),
        ),
        (StdioCapture::Forward, None) | (StdioCapture::Inherit, _) => (None, None, None, None),
    };
    // SAFETY: `job` is our job object; `process` is the new suspended process.
    let assigned = unsafe { AssignProcessToJobObject(prepared.job.0, process.0) };
    if assigned == 0 {
        // SAFETY: process is still suspended; terminate so it never runs unsandboxed.
        unsafe {
            TerminateProcess(process.0, 1);
        }
        let _ = join_drain(stdout_drain);
        let _ = join_drain(stderr_drain);
        join_copy(stdout_fwd);
        join_copy(stderr_fwd);
        return Err(last_error("AssignProcessToJobObject"));
    }
    // SAFETY: thread is the primary thread of the suspended process.
    let resumed = unsafe { ResumeThread(thread.0) };
    if resumed == Dword::MAX {
        unsafe {
            TerminateProcess(process.0, 1);
        }
        let _ = join_drain(stdout_drain);
        let _ = join_drain(stderr_drain);
        join_copy(stdout_fwd);
        join_copy(stderr_fwd);
        return Err(last_error("ResumeThread"));
    }
    // INFINITE is 0xFFFF_FFFF. Cap finite waits one below that.
    let wait_ms = match timeout {
        None => INFINITE,
        Some(d) => d.as_millis().min(u32::MAX as u128 - 1) as Dword,
    };
    // SAFETY: process handle stays valid until we return.
    let started = std::time::Instant::now();
    let wait = unsafe { WaitForSingleObject(process.0, wait_ms) };
    let mut timed_out = wait == WAIT_TIMEOUT;
    if timed_out {
        drop(std::mem::replace(
            &mut prepared.job,
            CloseOnDrop(ptr::null_mut()),
        ));
        // SAFETY: job close requests KILL_ON_JOB_CLOSE.
        let mut reap = unsafe { WaitForSingleObject(process.0, 5_000) };
        if reap != WAIT_OBJECT_0 {
            unsafe {
                TerminateProcess(process.0, 1);
            }
            reap = unsafe { WaitForSingleObject(process.0, 5_000) };
        }
        if reap != WAIT_OBJECT_0 {
            return Err(KernelError::Timeout);
        }
    } else if wait == WAIT_FAILED || wait != WAIT_OBJECT_0 {
        return Err(last_error("WaitForSingleObject"));
    }
    let mut code: Dword = 1;
    // SAFETY: process has exited; exit code pointer is valid.
    let got = unsafe { GetExitCodeProcess(process.0, &mut code) };
    if got == 0 {
        let _ = join_drain(stdout_drain);
        let _ = join_drain(stderr_drain);
        let _ = finish_forward(
            timed_out,
            &forward_stop,
            &forward_threads,
            stdout_fwd,
            stderr_fwd,
            started,
            timeout,
        );
        if timed_out {
            return Err(KernelError::Timeout);
        }
        return Err(last_error("GetExitCodeProcess"));
    }
    let applied = if prepared.wfp_skipped {
        KernelApply::WfpSkipped
    } else {
        KernelApply::Applied
    };
    let output = if capture == StdioCapture::Collect {
        Some(std::process::Output {
            status: ExitStatus::from_raw(code),
            stdout: join_drain(stdout_drain),
            stderr: join_drain(stderr_drain),
        })
    } else {
        drop((stdout_drain, stderr_drain));
        timed_out |= finish_forward(
            timed_out,
            &forward_stop,
            &forward_threads,
            stdout_fwd,
            stderr_fwd,
            started,
            timeout,
        );
        None
    };
    Ok((applied, ExitStatus::from_raw(code), output, timed_out))
}

fn inheritable_pipe(
    write_for_child: bool,
) -> Result<(CloseOnDrop, Option<CloseOnDrop>), KernelError> {
    let mut sa = SecurityAttributes {
        n_length: std::mem::size_of::<SecurityAttributes>() as Dword,
        lp_security_descriptor: ptr::null_mut(),
        b_inherit_handle: 1,
    };
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    // SAFETY: sa lives for the call; out handles are written by CreatePipe.
    let ok = unsafe { CreatePipe(&mut read, &mut write, &mut sa, 0) };
    if ok == 0 {
        return Err(last_error("CreatePipe"));
    }
    let read = CloseOnDrop(read);
    let write = CloseOnDrop(write);
    if write_for_child {
        // Parent keeps the read end; do not inherit it into the child.
        // SAFETY: read is a live pipe handle we own.
        let cleared = unsafe { SetHandleInformation(read.0, HANDLE_FLAG_INHERIT, 0) };
        if cleared == 0 {
            return Err(last_error("SetHandleInformation"));
        }
        Ok((write, Some(read)))
    } else {
        let cleared = unsafe { SetHandleInformation(write.0, HANDLE_FLAG_INHERIT, 0) };
        if cleared == 0 {
            return Err(last_error("SetHandleInformation"));
        }
        Ok((read, Some(write)))
    }
}

fn read_all(handle: CloseOnDrop) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let mut n: Dword = 0;
        // SAFETY: handle is a readable pipe; buf is valid.
        let ok = unsafe {
            ReadFile(
                handle.0,
                buf.as_mut_ptr(),
                buf.len() as Dword,
                &mut n,
                ptr::null_mut(),
            )
        };
        if ok == 0 || n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    out
}

fn drain_pipe(handle: CloseOnDrop) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || read_all(handle))
}

fn drain_forward(
    src: CloseOnDrop,
    dst: CloseOnDrop,
    stop: Arc<AtomicBool>,
    threads: Arc<Mutex<Vec<CloseOnDrop>>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || copy_pipe(src, dst, &stop, &threads))
}

fn register_forward_thread(threads: &Mutex<Vec<CloseOnDrop>>) {
    let mut dup = ptr::null_mut();
    // SAFETY: GetCurrentThread is a pseudo-handle. DuplicateHandle makes
    // a real handle this thread owns; the pseudo-handle must not be closed.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentThread(),
            GetCurrentProcess(),
            &mut dup,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return;
    }
    let mut guard = threads.lock().unwrap_or_else(|err| err.into_inner());
    guard.push(CloseOnDrop(dup));
}

fn forward_done(
    stdout_fwd: &Option<std::thread::JoinHandle<()>>,
    stderr_fwd: &Option<std::thread::JoinHandle<()>>,
) -> bool {
    let stdout_done = match stdout_fwd {
        None => true,
        Some(handle) => handle.is_finished(),
    };
    let stderr_done = match stderr_fwd {
        None => true,
        Some(handle) => handle.is_finished(),
    };
    stdout_done && stderr_done
}

fn finish_forward(
    timed_out: bool,
    stop: &AtomicBool,
    threads: &Mutex<Vec<CloseOnDrop>>,
    stdout_fwd: Option<std::thread::JoinHandle<()>>,
    stderr_fwd: Option<std::thread::JoinHandle<()>>,
    started: std::time::Instant,
    timeout: Option<Duration>,
) -> bool {
    let mut forced = timed_out;
    if let Some(limit) = timeout {
        let deadline = started + limit;
        while !forward_done(&stdout_fwd, &stderr_fwd) {
            if std::time::Instant::now() >= deadline {
                forced = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    if forced {
        stop.store(true, Ordering::Relaxed);
        // Cancel is a no-op unless the thread is already inside ReadFile
        // or WriteFile. Repeat it until the copy is done so a check of
        // `stop` that lost the race still unblocks.
        for _ in 0..500 {
            let registered = {
                let guard = threads.lock().unwrap_or_else(|err| err.into_inner());
                for handle in guard.iter() {
                    // SAFETY: handle is the duplicated copy thread.
                    unsafe {
                        CancelSynchronousIo(handle.0);
                    }
                }
                guard.len()
            };
            let stdout_done = match &stdout_fwd {
                None => true,
                Some(handle) => handle.is_finished(),
            };
            let stderr_done = match &stderr_fwd {
                None => true,
                Some(handle) => handle.is_finished(),
            };
            if (stdout_done && stderr_done) || registered == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    join_copy(stdout_fwd);
    join_copy(stderr_fwd);
    forced
}

fn join_drain(handle: Option<std::thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    handle.and_then(|h| h.join().ok()).unwrap_or_default()
}

fn join_copy(handle: Option<std::thread::JoinHandle<()>>) {
    if let Some(h) = handle {
        let _ = h.join();
    }
}

fn duplicate_std_handle(std_id: Dword, write: bool) -> Result<CloseOnDrop, KernelError> {
    // SAFETY: GetStdHandle is always valid to call.
    let parent = unsafe { GetStdHandle(std_id) };
    if parent.is_null() || parent == INVALID_HANDLE_VALUE {
        return open_nul(write);
    }
    let current = unsafe { GetCurrentProcess() };
    let mut dup = ptr::null_mut();
    // SAFETY: parent is this process's std handle; inherit=0 so the child
    // does not also get this copy (it has the pipe write end).
    let ok = unsafe {
        DuplicateHandle(
            current,
            parent,
            current,
            &mut dup,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return open_nul(write);
    }
    Ok(CloseOnDrop(dup))
}

fn copy_pipe(
    src: CloseOnDrop,
    dst: CloseOnDrop,
    stop: &AtomicBool,
    threads: &Mutex<Vec<CloseOnDrop>>,
) {
    register_forward_thread(threads);
    if stop.load(Ordering::Relaxed) {
        return;
    }
    let mut buf = [0u8; 16 * 1024];
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let mut n: Dword = 0;
        // SAFETY: src is a readable pipe we own.
        let ok = unsafe {
            ReadFile(
                src.0,
                buf.as_mut_ptr(),
                buf.len() as Dword,
                &mut n,
                ptr::null_mut(),
            )
        };
        if ok == 0 || n == 0 || stop.load(Ordering::Relaxed) {
            break;
        }
        let mut wrote: Dword = 0;
        // SAFETY: dst is a duplicated parent std handle we own.
        let ok = unsafe { WriteFile(dst.0, buf.as_ptr(), n, &mut wrote, ptr::null_mut()) };
        if ok == 0 {
            break;
        }
    }
}

fn dest_deny_paths(policy: &KernelPolicy) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for deny in policy.dest_denies() {
        if !paths.iter().any(|p| p == &deny.path) {
            paths.push(deny.path.clone());
        }
    }
    paths
}

fn deny_dest_aces(paths: &[PathBuf], sid: Handle) -> Result<Vec<AclRestore>, KernelError> {
    let mut guards = Vec::with_capacity(paths.len());
    for path in paths {
        if !path.exists() {
            continue;
        }
        match deny_dest_ace(path, sid) {
            Ok(guard) => guards.push(guard),
            Err(err) => {
                let _ = restore_guards(&mut guards);
                return Err(err);
            }
        }
    }
    Ok(guards)
}

#[cfg(test)]
thread_local! {
    static TEST_ACE_FAIL_ON: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn fail_next_ace_on(path: PathBuf) {
    TEST_ACE_FAIL_ON.with(|c| *c.borrow_mut() = Some(path));
}

fn deny_dest_ace(path: &Path, sid: Handle) -> Result<AclRestore, KernelError> {
    #[cfg(test)]
    if TEST_ACE_FAIL_ON.with(|c| {
        let hit = c.borrow().as_ref().is_some_and(|p| p.as_path() == path);
        if hit {
            *c.borrow_mut() = None;
        }
        hit
    }) {
        return Err(KernelError::Apply("test dest-deny ACE fail".into()));
    }
    let inherit = if path.is_dir() {
        SUB_CONTAINERS_AND_OBJECTS_INHERIT
    } else {
        NO_INHERITANCE
    };
    set_acl_entry(path, sid, GENERIC_ALL, DENY_ACCESS, inherit)
}

fn rw_grant_paths(policy: &KernelPolicy) -> Vec<PathBuf> {
    grant_paths(policy, KernelAccess::ReadWrite)
}

fn read_grant_paths(policy: &KernelPolicy) -> Vec<PathBuf> {
    grant_paths(policy, KernelAccess::Read)
}

fn grant_paths(policy: &KernelPolicy, access: KernelAccess) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for grant in policy.grants() {
        if grant.access == access && !paths.iter().any(|p| p == &grant.path) {
            paths.push(grant.path.clone());
        }
    }
    paths
}

fn grant_write_aces(paths: &[PathBuf], sid: Handle) -> Result<Vec<AclRestore>, KernelError> {
    let mut guards = Vec::with_capacity(paths.len());
    for path in paths {
        match grant_write_ace(path, sid) {
            Ok(guard) => guards.push(guard),
            Err(err) => {
                let _ = restore_guards(&mut guards);
                return Err(err);
            }
        }
    }
    Ok(guards)
}

fn grant_write_ace(path: &Path, sid: Handle) -> Result<AclRestore, KernelError> {
    set_acl_entry(
        path,
        sid,
        GENERIC_ALL,
        GRANT_ACCESS,
        SUB_CONTAINERS_AND_OBJECTS_INHERIT,
    )
}

fn set_acl_entry(
    path: &Path,
    sid: Handle,
    permissions: Dword,
    mode: u32,
    inheritance: Dword,
) -> Result<AclRestore, KernelError> {
    set_named_ace(
        &wide_path(path),
        SE_FILE_OBJECT,
        sid,
        permissions,
        mode,
        inheritance,
    )
}

fn set_named_ace(
    wide: &[u16],
    object_type: u32,
    sid: Handle,
    permissions: Dword,
    mode: u32,
    inheritance: Dword,
) -> Result<AclRestore, KernelError> {
    let mut wide = wide.to_vec();
    let mut owner = ptr::null_mut();
    let mut group = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut sacl = ptr::null_mut();
    let mut sd = ptr::null_mut();
    // SAFETY: `wide` is a NUL-terminated path; out pointers are written by the API.
    let got = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            object_type,
            DACL_SECURITY_INFORMATION,
            &mut owner,
            &mut group,
            &mut dacl,
            &mut sacl,
            &mut sd,
        )
    };
    if got != 0 {
        return Err(win32_error("GetNamedSecurityInfoW", got));
    }
    let sd = LocalMem(sd);
    let mut entry = ExplicitAccessW {
        grf_access_permissions: permissions,
        grf_access_mode: mode,
        grf_inheritance: inheritance,
        trustee: TrusteeW {
            p_multiple_trustee: ptr::null_mut(),
            multiple_trustee_operation: NO_MULTIPLE_TRUSTEE,
            trustee_form: TRUSTEE_IS_SID,
            trustee_type: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstr_name: sid,
        },
    };
    let mut new_acl = ptr::null_mut();
    // SAFETY: `entry` lives for the call; `dacl` is the current DACL inside `sd`.
    let set = unsafe { SetEntriesInAclW(1, &mut entry, dacl, &mut new_acl) };
    if set != 0 {
        return Err(win32_error("SetEntriesInAclW", set));
    }
    let new_acl = LocalMem(new_acl);
    // SAFETY: `wide` is a writable NUL-terminated path; `new_acl` is a valid ACL.
    let applied = unsafe {
        SetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            object_type,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            new_acl.0,
            ptr::null_mut(),
        )
    };
    if applied != 0 {
        return Err(win32_error("SetNamedSecurityInfoW", applied));
    }
    Ok(AclRestore {
        path: wide,
        object_type,
        _sd: sd,
        dacl,
        restored: false,
    })
}

fn open_current_process_token() -> Result<CloseOnDrop, KernelError> {
    let mut process_token = ptr::null_mut();
    // SAFETY: current process handle is valid.
    let opened =
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_PRIMARY_MASK, &mut process_token) };
    if opened == 0 {
        return Err(last_error("OpenProcessToken"));
    }
    Ok(CloseOnDrop(process_token))
}

fn create_restricted_token(process_token: Handle, sid: Handle) -> Result<CloseOnDrop, KernelError> {
    let restrict = SidAndAttributes { sid, attributes: 0 };
    let mut restricted = ptr::null_mut();
    // DISABLE_MAX_PRIVILEGE disables every privilege except
    // SeChangeNotifyPrivilege. These stay off: SeDebugPrivilege,
    // SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege,
    // SeLoadDriverPrivilege, SeTcbPrivilege. Do not drop the flag.
    // SAFETY: `process_token` is an open process token; `restrict` lives for the call.
    let ok = unsafe {
        CreateRestrictedToken(
            process_token,
            DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED,
            0,
            ptr::null(),
            0,
            ptr::null(),
            1,
            &restrict,
            &mut restricted,
        )
    };
    if ok == 0 {
        return Err(last_error("CreateRestrictedToken"));
    }
    Ok(CloseOnDrop(restricted))
}

fn duplicate_primary_token(token: Handle) -> Result<CloseOnDrop, KernelError> {
    let mut primary = ptr::null_mut();
    // SAFETY: `token` is an open token; we request a primary token.
    let dup = unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_PRIMARY_MASK,
            ptr::null_mut(),
            SECURITY_IMPERSONATION,
            TOKEN_PRIMARY,
            &mut primary,
        )
    };
    if dup == 0 {
        return Err(last_error("DuplicateTokenEx"));
    }
    Ok(CloseOnDrop(primary))
}

fn create_write_restricted_token(sid: Handle) -> Result<CloseOnDrop, KernelError> {
    let process_token = open_current_process_token()?;
    let restricted = create_restricted_token(process_token.0, sid)?;
    let primary = duplicate_primary_token(restricted.0)?;
    // Objects the child creates (the MSYS section) need the restricting
    // SID on their DACL. Ignore failure: the token is still restricted.
    let _ = grant_default_dacl(primary.0, sid);
    Ok(primary)
}

const TOKEN_DEFAULT_DACL: u32 = 6;

#[repr(C)]
struct TokenDefaultDacl {
    default_dacl: Handle,
}

fn grant_default_dacl(token: Handle, sid: Handle) -> Result<(), KernelError> {
    let mut bytes = 0u32;
    // SAFETY: size probe; a short buffer is the expected first result.
    unsafe {
        GetTokenInformation(token, TOKEN_DEFAULT_DACL, ptr::null_mut(), 0, &mut bytes);
    }
    if bytes == 0 {
        return Err(last_error("GetTokenInformation TokenDefaultDacl"));
    }
    let len = bytes;
    let mut buf = vec![0u64; len.div_ceil(8) as usize];
    // SAFETY: `buf` is at least `len` bytes and pointer-aligned.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TOKEN_DEFAULT_DACL,
            buf.as_mut_ptr().cast(),
            len,
            &mut bytes,
        )
    };
    if ok == 0 {
        return Err(last_error("GetTokenInformation TokenDefaultDacl"));
    }
    let current = unsafe { &*buf.as_ptr().cast::<TokenDefaultDacl>() };
    let mut entry = ExplicitAccessW {
        grf_access_permissions: GENERIC_ALL,
        grf_access_mode: GRANT_ACCESS,
        grf_inheritance: NO_INHERITANCE,
        trustee: TrusteeW {
            p_multiple_trustee: ptr::null_mut(),
            multiple_trustee_operation: NO_MULTIPLE_TRUSTEE,
            trustee_form: TRUSTEE_IS_SID,
            trustee_type: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstr_name: sid,
        },
    };
    let mut new_acl = ptr::null_mut();
    // SAFETY: `entry` lives for the call; `current.default_dacl` is inside `buf`.
    let set = unsafe { SetEntriesInAclW(1, &mut entry, current.default_dacl, &mut new_acl) };
    if set != 0 {
        return Err(win32_error("SetEntriesInAclW default DACL", set));
    }
    let new_acl = LocalMem(new_acl);
    let mut info = TokenDefaultDacl {
        default_dacl: new_acl.0,
    };
    // SAFETY: `info.default_dacl` is the ACL we just built.
    let applied = unsafe {
        SetTokenInformation(
            token,
            TOKEN_DEFAULT_DACL,
            (&raw mut info).cast(),
            std::mem::size_of::<TokenDefaultDacl>() as Dword,
        )
    };
    if applied == 0 {
        return Err(last_error("SetTokenInformation TokenDefaultDacl"));
    }
    Ok(())
}

fn create_kill_job() -> Result<CloseOnDrop, KernelError> {
    // SAFETY: unnamed job; attributes are NULL.
    let job = unsafe { CreateJobObjectW(ptr::null_mut(), ptr::null()) };
    if job.is_null() || job == INVALID_HANDLE_VALUE {
        return Err(last_error("CreateJobObjectW"));
    }
    let job = CloseOnDrop(job);
    let mut info = JobobjectExtendedLimitInformation {
        basic_limit_information: JobobjectBasicLimitInformation {
            per_process_user_time_limit: 0,
            per_job_user_time_limit: 0,
            limit_flags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            minimum_working_set_size: 0,
            maximum_working_set_size: 0,
            active_process_limit: 0,
            affinity: 0,
            priority_class: 0,
            scheduling_class: 0,
        },
        io_info: IoCounters {
            read_operation_count: 0,
            write_operation_count: 0,
            other_operation_count: 0,
            read_transfer_count: 0,
            write_transfer_count: 0,
            other_transfer_count: 0,
        },
        process_memory_limit: 0,
        job_memory_limit: 0,
        peak_process_memory_used: 0,
        peak_job_memory_used: 0,
    };
    // SAFETY: `info` matches JobObjectExtendedLimitInformation.
    let set = unsafe {
        SetInformationJobObject(
            job.0,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            (&raw mut info).cast(),
            std::mem::size_of::<JobobjectExtendedLimitInformation>() as Dword,
        )
    };
    if set == 0 {
        return Err(last_error("SetInformationJobObject"));
    }
    let mut ui = JobobjectBasicUiRestrictions {
        ui_restrictions_class: UI_RESTRICTIONS,
    };
    // SAFETY: `ui` matches JOBOBJECT_BASIC_UI_RESTRICTIONS.
    let ui_set = unsafe {
        SetInformationJobObject(
            job.0,
            JOB_OBJECT_BASIC_UI_RESTRICTIONS,
            (&raw mut ui).cast(),
            std::mem::size_of::<JobobjectBasicUiRestrictions>() as Dword,
        )
    };
    if ui_set == 0 {
        return Err(last_error("SetInformationJobObject UI restrictions"));
    }
    Ok(job)
}

#[repr(C)]
struct JobobjectBasicUiRestrictions {
    ui_restrictions_class: Dword,
}

fn environment_block(cmd: &mut Command) -> Vec<u16> {
    let pairs = super::child_env_pairs(cmd);
    let mut out = Vec::new();
    for (key, value) in pairs {
        out.extend(key.encode_wide());
        out.push(u16::from(b'='));
        out.extend(value.encode_wide());
        out.push(0);
    }
    if out.is_empty() {
        out.push(0);
    }
    out.push(0);
    out
}

fn wrap_command_line(
    helper: &Path,
    cmd: &Command,
) -> Result<(Vec<u16>, Vec<u16>, Option<Vec<u16>>), KernelError> {
    let (_orig_app, orig_line, cwd) = command_line(cmd)?;
    let mut line = Vec::new();
    append_quoted(&mut line, helper.as_os_str());
    line.extend_from_slice(&[0x20, 0x2d, 0x2d, 0x20]);
    let orig = orig_line
        .last()
        .is_some_and(|c| *c == 0)
        .then(|| &orig_line[..orig_line.len() - 1])
        .unwrap_or(orig_line.as_slice());
    line.extend_from_slice(orig);
    line.push(0);
    Ok((wide_path(helper), line, cwd))
}

fn command_line(cmd: &Command) -> Result<(Vec<u16>, Vec<u16>, Option<Vec<u16>>), KernelError> {
    let program = resolve_program(cmd.get_program())?;
    let mut line = Vec::new();
    append_quoted(&mut line, OsStr::new(&program));
    for arg in cmd.get_args() {
        line.push(0x20);
        append_quoted(&mut line, arg);
    }
    line.push(0);
    let cwd = cmd.get_current_dir().map(wide_path);
    Ok((wide_path(Path::new(&program)), line, cwd))
}

fn resolve_program(program: &OsStr) -> Result<PathBuf, KernelError> {
    let path = Path::new(program);
    if path.components().count() > 1 || path.is_absolute() {
        if path.exists() {
            return Ok(path.to_path_buf());
        }
        return Err(KernelError::Apply(format!(
            "{}: not found",
            program.to_string_lossy()
        )));
    }
    let name = wide_os(program);
    let ext: Vec<u16> = OsStr::new(".exe")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut buf = vec![0u16; 32768];
    // SAFETY: `name` and `ext` are NUL-terminated; `buf` is the output.
    let n = unsafe {
        SearchPathW(
            ptr::null(),
            name.as_ptr(),
            ext.as_ptr(),
            buf.len() as Dword,
            buf.as_mut_ptr(),
            ptr::null_mut(),
        )
    };
    if n == 0 || n as usize >= buf.len() {
        if path.exists() {
            return Ok(path.to_path_buf());
        }
        return Err(KernelError::Apply(format!(
            "{}: not found",
            program.to_string_lossy()
        )));
    }
    Ok(PathBuf::from(OsString::from_wide(&buf[..n as usize])))
}

fn append_quoted(out: &mut Vec<u16>, arg: &OsStr) {
    let wide: Vec<u16> = arg.encode_wide().collect();
    let needs_quotes = wide
        .iter()
        .any(|&c| c == 0x20 || c == 0x09 || c == 0x22 || c == 0);
    if !needs_quotes && !wide.is_empty() {
        out.extend_from_slice(&wide);
        return;
    }
    out.push(0x22);
    let mut slashes = 0usize;
    for &c in &wide {
        if c == 0x5c {
            slashes += 1;
            continue;
        }
        if c == 0x22 {
            out.extend(std::iter::repeat_n(0x5c, slashes * 2 + 1));
            out.push(0x22);
        } else {
            out.extend(std::iter::repeat_n(0x5c, slashes));
            out.push(c);
        }
        slashes = 0;
    }
    out.extend(std::iter::repeat_n(0x5c, slashes * 2));
    out.push(0x22);
}

#[cfg(test)]
const TOKEN_PRIVILEGES_CLASS: u32 = 3;
#[cfg(test)]
const SE_PRIVILEGE_ENABLED: Dword = 0x0000_0002;

/// `Some(true)` enabled, `Some(false)` present but disabled, `None` absent.
#[cfg(test)]
fn privilege_enabled(token: Handle, name: &str) -> Result<Option<bool>, KernelError> {
    let wide = wide_os(OsStr::new(name));
    let mut want = Luid {
        low_part: 0,
        high_part: 0,
    };
    // SAFETY: `wide` is a NUL-terminated privilege name.
    let looked = unsafe { LookupPrivilegeValueW(ptr::null(), wide.as_ptr(), &mut want) };
    if looked == 0 {
        return Err(last_error("LookupPrivilegeValueW"));
    }
    let mut bytes = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            TOKEN_PRIVILEGES_CLASS,
            ptr::null_mut(),
            0,
            &mut bytes,
        );
    }
    if bytes < 4 {
        return Err(last_error("GetTokenInformation TokenPrivileges"));
    }
    let len = bytes;
    let mut buf = vec![0u64; len.div_ceil(8) as usize];
    // SAFETY: `buf` is at least `len` bytes and 8-byte aligned.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TOKEN_PRIVILEGES_CLASS,
            buf.as_mut_ptr().cast(),
            len,
            &mut bytes,
        )
    };
    if ok == 0 {
        return Err(last_error("GetTokenInformation TokenPrivileges"));
    }
    let raw = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, bytes as usize) };
    let count = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let stride = std::mem::size_of::<LuidAndAttributes>();
    for i in 0..count as usize {
        let start = 4 + i * stride;
        let end = start + stride;
        if end > raw.len() {
            break;
        }
        // SAFETY: `start` is inside `raw`. LUID_AND_ATTRIBUTES is 4-byte aligned
        // and TOKEN_PRIVILEGES places the first entry at offset 4.
        let entry = unsafe { &*raw[start..].as_ptr().cast::<LuidAndAttributes>() };
        if entry.luid.low_part == want.low_part && entry.luid.high_part == want.high_part {
            return Ok(Some(entry.attributes & SE_PRIVILEGE_ENABLED != 0));
        }
    }
    Ok(None)
}

pub(super) fn appcontainer_creates() -> u32 {
    windows_net::appcontainer_creates()
}

pub(super) fn reset_appcontainer_creates() {
    windows_net::reset_appcontainer_creates();
}

#[cfg(test)]
mod ace_tests {
    use super::*;
    use std::path::Path;

    const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
    const ACL_SIZE_INFORMATION: u32 = 2;

    #[repr(C)]
    #[allow(dead_code)]
    struct AceHeader {
        ace_type: u8,
        ace_flags: u8,
        ace_size: u16,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct AccessDeniedAce {
        header: AceHeader,
        mask: Dword,
        sid_start: Dword,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct AclSizeInformation {
        ace_count: Dword,
        acl_bytes_in_use: Dword,
        acl_bytes_free: Dword,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetAclInformation(
            p_acl: Handle,
            p_acl_information: *mut core::ffi::c_void,
            n_acl_information_length: Dword,
            dw_acl_information_class: u32,
        ) -> Bool;
        fn GetAce(p_acl: Handle, dw_ace_index: Dword, p_ace: *mut Handle) -> Bool;
        fn EqualSid(p_sid1: Handle, p_sid2: Handle) -> Bool;
    }

    fn dacl_has_deny_ace(path: &Path, sid: Handle) -> bool {
        let wide = wide_path(path);
        let mut owner = ptr::null_mut();
        let mut group = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut sacl = ptr::null_mut();
        let mut sd = ptr::null_mut();
        // SAFETY: `wide` is a NUL-terminated path; out pointers are written by the API.
        let got = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                &mut owner,
                &mut group,
                &mut dacl,
                &mut sacl,
                &mut sd,
            )
        };
        assert_eq!(got, 0, "GetNamedSecurityInfoW first dest failed ({got})");
        let _sd = LocalMem(sd);
        if dacl.is_null() {
            return false;
        }
        let mut info = AclSizeInformation {
            ace_count: 0,
            acl_bytes_in_use: 0,
            acl_bytes_free: 0,
        };
        // SAFETY: `dacl` is the DACL inside `_sd`; `info` matches AclSizeInformation.
        let queried = unsafe {
            GetAclInformation(
                dacl,
                (&raw mut info).cast(),
                std::mem::size_of::<AclSizeInformation>() as Dword,
                ACL_SIZE_INFORMATION,
            )
        };
        assert_ne!(queried, 0, "GetAclInformation first dest");
        for i in 0..info.ace_count {
            let mut ace = ptr::null_mut();
            // SAFETY: `dacl` is valid for AceCount entries; `ace` is written by GetAce.
            let found = unsafe { GetAce(dacl, i, &mut ace) };
            assert_ne!(found, 0, "GetAce {i}");
            // SAFETY: GetAce returned a pointer into `dacl`.
            let header = unsafe { &*ace.cast::<AceHeader>() };
            if header.ace_type != ACCESS_DENIED_ACE_TYPE {
                continue;
            }
            // SAFETY: ACCESS_DENIED_ACE layout; SidStart is the SID bytes.
            let ace_sid =
                unsafe { (&raw const (*ace.cast::<AccessDeniedAce>()).sid_start) as Handle };
            // SAFETY: both pointers are SIDs (ACE SidStart and RestrictedSid).
            if unsafe { EqualSid(ace_sid, sid) } != 0 {
                return true;
            }
        }
        false
    }

    #[test]
    fn deny_dest_aces_rolls_back_on_second_path_error() {
        let dir = tempfile::TempDir::new().expect("ws");
        let first = dir.path().join("a.env");
        let second = dir.path().join("b.env");
        std::fs::write(&first, "1").expect("first");
        std::fs::write(&second, "2").expect("second");
        let sid = RestrictedSid::new().expect("sid");
        fail_next_ace_on(second.clone());
        let err = match deny_dest_aces(&[first.clone(), second], sid.0) {
            Err(err) => err,
            Ok(_) => panic!("second ACE must fail"),
        };
        assert!(
            matches!(err, KernelError::Apply(_)),
            "mid-loop ACE fail is Apply: {err}"
        );
        assert!(
            !dacl_has_deny_ace(&first, sid.0),
            "first dest must not keep a leftover DENY ACE after rollback"
        );
        drop(sid);
    }

    #[test]
    fn restricted_token_keeps_traverse_and_drops_admin_privileges() {
        let sid = RestrictedSid::new().expect("sid");
        let token = create_write_restricted_token(sid.0).expect("token");
        let traverse = privilege_enabled(token.0, "SeChangeNotifyPrivilege").expect("lookup");
        assert_eq!(
            traverse,
            Some(true),
            "SeChangeNotifyPrivilege must stay enabled, got {traverse:?}"
        );
        for name in [
            "SeDebugPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeTcbPrivilege",
        ] {
            let state =
                privilege_enabled(token.0, name).unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_ne!(
                state,
                Some(true),
                "{name} must stay disabled, got {state:?}"
            );
        }
    }
}

#[cfg(test)]
mod env_block_tests {
    use super::environment_block;
    use std::process::Command;

    fn block_has_key(block: &[u16], key: &str) -> bool {
        let mut entry = Vec::new();
        for unit in block {
            if *unit == 0 {
                if entry.is_empty() {
                    break;
                }
                let text = String::from_utf16_lossy(&entry);
                if text
                    .split_once('=')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case(key))
                {
                    return true;
                }
                entry.clear();
            } else {
                entry.push(*unit);
            }
        }
        false
    }

    #[test]
    fn env_remove_drops_an_inherited_name() {
        let Some((key, _)) = std::env::vars_os().find(|(name, _)| {
            let name = name.to_string_lossy();
            !name.eq_ignore_ascii_case("PATH") && !name.eq_ignore_ascii_case("SystemRoot")
        }) else {
            return;
        };
        let name = key.to_string_lossy().into_owned();
        let mut cmd = Command::new("cmd");
        for (inherited, _) in std::env::vars_os() {
            cmd.env_remove(inherited);
        }
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        let block = environment_block(&mut cmd);
        assert!(
            !block_has_key(&block, &name),
            "{name} stayed in the child block after env_remove"
        );
        if std::env::var_os("PATH").is_some() {
            assert!(block_has_key(&block, "PATH"), "PATH was not restored");
        }
    }

    #[test]
    fn env_clear_drops_an_inherited_name() {
        let Some((key, _)) = std::env::vars_os().find(|(name, _)| {
            let name = name.to_string_lossy();
            !name.eq_ignore_ascii_case("PATH") && !name.eq_ignore_ascii_case("SystemRoot")
        }) else {
            return;
        };
        let name = key.to_string_lossy().into_owned();
        let mut cmd = Command::new("cmd");
        cmd.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        if let Some(root) = std::env::var_os("SystemRoot") {
            cmd.env("SystemRoot", root);
        }
        let block = environment_block(&mut cmd);
        assert!(
            !block_has_key(&block, &name),
            "{name} stayed in the child block after env_clear"
        );
        if std::env::var_os("PATH").is_some() {
            assert!(block_has_key(&block, "PATH"), "PATH was not restored");
        }
        if std::env::var_os("SystemRoot").is_some() {
            assert!(
                block_has_key(&block, "SystemRoot"),
                "SystemRoot was not restored"
            );
        }
    }
}
