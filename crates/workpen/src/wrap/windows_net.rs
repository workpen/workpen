//! Unique helper PE plus AppContainer plus package-scoped WFP.
//!
//! Not a dest-parent-copy. Userspace WFP has no process-id condition, so
//! a path-wide `cmd.exe` filter is out of scope. The helper is a unique
//! PE; the AppContainer SID is unique per spawn; descendants inherit the
//! package. WFP BLOCKs that package SID (and the helper APP_ID) only.

use std::ffi::OsStr;
use std::fs;
use std::mem;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Bool, Dword, Handle, KernelError, last_error, wide_os, wide_path, win32_error};

const HELPER_PE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/workpen-net-helper.exe"));

const RPC_C_AUTHN_WINNT: u32 = 10;
const FWPM_SESSION_FLAG_DYNAMIC: u32 = 0x0000_0001;
const FWP_UINT8: u32 = 1;
const FWP_BYTE_BLOB_TYPE: u32 = 12;
const FWP_SID: u32 = 13;
const FWP_MATCH_EQUAL: u32 = 0;
const FWP_ACTION_FLAG_TERMINATING: u32 = 0x0000_1000;
const FWP_ACTION_BLOCK: u32 = 0x0000_0001 | FWP_ACTION_FLAG_TERMINATING;

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
    Guid {
        data1,
        data2,
        data3,
        data4,
    }
}

const FWPM_LAYER_ALE_AUTH_CONNECT_V4: Guid = guid(
    0xc38d57d1,
    0x05a7,
    0x4c33,
    [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82],
);
const FWPM_LAYER_ALE_AUTH_CONNECT_V6: Guid = guid(
    0x4a72393b,
    0x319f,
    0x44bc,
    [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4],
);
const FWPM_CONDITION_ALE_APP_ID: Guid = guid(
    0xd78e1e87,
    0x8644,
    0x4ea5,
    [0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71],
);
const FWPM_CONDITION_ALE_PACKAGE_ID: Guid = guid(
    0x71bc78fa,
    0xf17c,
    0x4997,
    [0xa6, 0x02, 0x6a, 0xbb, 0x26, 0x1f, 0x35, 0x1c],
);

#[repr(C)]
struct SecurityCapabilities {
    app_container_sid: Handle,
    capabilities: *mut SidAndAttributes,
    capability_count: Dword,
    reserved: Dword,
}

#[repr(C)]
struct SidAndAttributes {
    sid: Handle,
    attributes: Dword,
}

#[repr(C)]
struct FwpmDisplayData0 {
    name: *mut u16,
    description: *mut u16,
}

#[repr(C)]
struct FwpmSession0 {
    session_key: Guid,
    display_data: FwpmDisplayData0,
    flags: u32,
    txn_wait_timeout_in_msec: u32,
    process_id: Dword,
    sid: Handle,
    username: *mut u16,
    kernel_mode: Bool,
}

#[repr(C)]
struct FwpByteBlob {
    size: u32,
    data: *mut u8,
}

#[repr(C)]
struct FwpValue0 {
    data_type: u32,
    value: usize,
}

#[repr(C)]
struct FwpmAction0 {
    action_type: u32,
    filter_type: Guid,
}

#[repr(C)]
struct FwpmFilterCondition0 {
    field_key: Guid,
    match_type: u32,
    condition_value: FwpValue0,
}

#[repr(C)]
struct FwpmFilter0 {
    filter_key: Guid,
    display_data: FwpmDisplayData0,
    flags: u32,
    provider_key: *mut Guid,
    provider_data: FwpByteBlob,
    layer_key: Guid,
    sub_layer_key: Guid,
    weight: FwpValue0,
    num_filter_conditions: u32,
    filter_condition: *mut FwpmFilterCondition0,
    action: FwpmAction0,
    raw_context: u64,
    reserved: *mut Guid,
    filter_id: u64,
    effective_weight: FwpValue0,
}

type CreateAppContainerTokenFn =
    unsafe extern "system" fn(Handle, *const SecurityCapabilities, *mut Handle) -> Bool;

#[link(name = "userenv")]
unsafe extern "system" {
    fn CreateAppContainerProfile(
        psz_app_container_name: *const u16,
        psz_display_name: *const u16,
        psz_description: *const u16,
        p_capabilities: *const SidAndAttributes,
        dw_capability_count: Dword,
        pp_sid_app_container_sid: *mut Handle,
    ) -> i32;
    fn DeriveAppContainerSidFromAppContainerName(
        psz_app_container_name: *const u16,
        ppsid_app_container_sid: *mut Handle,
    ) -> i32;
    fn DeleteAppContainerProfile(psz_app_container_name: *const u16) -> i32;
}

#[link(name = "fwpuclnt")]
unsafe extern "system" {
    fn FwpmEngineOpen0(
        server_name: *const u16,
        authn_service: u32,
        auth_identity: *mut core::ffi::c_void,
        session: *const FwpmSession0,
        engine_handle: *mut Handle,
    ) -> u32;
    fn FwpmEngineClose0(engine_handle: Handle) -> u32;
    fn FwpmFilterAdd0(
        engine_handle: Handle,
        filter: *const FwpmFilter0,
        sd: *mut core::ffi::c_void,
        id: *mut u64,
    ) -> u32;
    fn FwpmGetAppIdFromFileName0(file_name: *const u16, app_id: *mut *mut FwpByteBlob) -> u32;
    fn FwpmFreeMemory0(p: *mut *mut core::ffi::c_void);
}

pub(super) struct AppContainerProfile {
    name: Vec<u16>,
    sid: Handle,
}

impl AppContainerProfile {
    pub(super) fn create() -> Result<Self, KernelError> {
        let suffix = unique_suffix();
        let raw = format!("wpnh.{suffix}");
        let name = wide_os(OsStr::new(&raw));
        let display = wide_os(OsStr::new(&raw));
        let desc = wide_os(OsStr::new("workpen"));
        let mut sid = ptr::null_mut();
        // SAFETY: name/display/desc are NUL-terminated; no capabilities.
        let hr = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                display.as_ptr(),
                desc.as_ptr(),
                ptr::null(),
                0,
                &mut sid,
            )
        };
        if hr != 0 || sid.is_null() {
            sid = ptr::null_mut();
            // SAFETY: leftover profile from a crashed spawn; name is NUL-terminated.
            let derived =
                unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
            if derived != 0 || sid.is_null() {
                return Err(hresult_error("CreateAppContainerProfile", hr));
            }
        }
        Ok(Self { name, sid })
    }

    pub(super) fn sid(&self) -> Handle {
        self.sid
    }
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        if !self.sid.is_null() {
            // SAFETY: sid came from CreateAppContainerProfile or Derive.
            unsafe {
                super::free_sid(self.sid);
            }
            self.sid = ptr::null_mut();
        }
        if !self.name.is_empty() {
            // SAFETY: name is the profile we created or reused.
            unsafe {
                DeleteAppContainerProfile(self.name.as_ptr());
            }
        }
    }
}

pub(super) struct HelperFile {
    path: PathBuf,
}

impl HelperFile {
    pub(super) fn install(dir: &Path) -> Result<Self, KernelError> {
        let path = dir.join(format!(".wpnh-{}.exe", unique_suffix()));
        fs::write(&path, HELPER_PE)
            .map_err(|e| KernelError::Apply(format!("write net helper {}: {e}", path.display())))?;
        Ok(Self { path })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for HelperFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub(super) struct WfpSession {
    engine: Handle,
}

impl WfpSession {
    pub(super) fn apply(package_sid: Handle, helper: &Path) -> Result<Self, KernelError> {
        let mut name = wide_os(OsStr::new("workpen-net"));
        let mut session: FwpmSession0 = unsafe { mem::zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.display_data.name = name.as_mut_ptr();
        let mut engine = ptr::null_mut();
        // SAFETY: local engine; session lives for the call.
        let err = unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null_mut(),
                &session,
                &mut engine,
            )
        };
        if err != 0 || engine.is_null() {
            return Err(win32_error("FwpmEngineOpen0", err));
        }
        let wfp = Self { engine };
        add_sid_blocks(engine, package_sid, &mut name)?;
        add_app_id_blocks(engine, helper, &mut name)?;
        Ok(wfp)
    }
}

impl Drop for WfpSession {
    fn drop(&mut self) {
        if !self.engine.is_null() {
            // SAFETY: engine from FwpmEngineOpen0; dynamic filters die with it.
            unsafe {
                FwpmEngineClose0(self.engine);
            }
            self.engine = ptr::null_mut();
        }
    }
}

pub(super) fn create_appcontainer_token(
    base: Handle,
    package_sid: Handle,
) -> Result<Handle, KernelError> {
    let create = load_create_appcontainer_token()?;
    let caps = SecurityCapabilities {
        app_container_sid: package_sid,
        capabilities: ptr::null_mut(),
        capability_count: 0,
        reserved: 0,
    };
    let mut out = ptr::null_mut();
    // SAFETY: base is a primary token we own; caps.sid lives for the call.
    let ok = unsafe { create(base, &caps, &mut out) };
    if ok == 0 || out.is_null() {
        return Err(last_error("CreateAppContainerToken"));
    }
    Ok(out)
}

fn load_create_appcontainer_token() -> Result<CreateAppContainerTokenFn, KernelError> {
    let module = wide_os(OsStr::new("kernelbase.dll"));
    // SAFETY: module is NUL-terminated.
    let handle = unsafe { super::GetModuleHandleW(module.as_ptr()) };
    if handle.is_null() {
        return Err(last_error("GetModuleHandleW kernelbase.dll"));
    }
    // SAFETY: handle is kernelbase; name is a static C string.
    let proc = unsafe { super::GetProcAddress(handle, c"CreateAppContainerToken".as_ptr().cast()) };
    if proc.is_null() {
        return Err(KernelError::Apply(
            "CreateAppContainerToken is not available".into(),
        ));
    }
    // SAFETY: documented kernelbase export; system calling convention.
    Ok(unsafe { mem::transmute::<_, CreateAppContainerTokenFn>(proc) })
}

fn add_sid_blocks(
    engine: Handle,
    package_sid: Handle,
    name: &mut [u16],
) -> Result<(), KernelError> {
    for layer in [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    ] {
        let mut cond: FwpmFilterCondition0 = unsafe { mem::zeroed() };
        cond.field_key = FWPM_CONDITION_ALE_PACKAGE_ID;
        cond.match_type = FWP_MATCH_EQUAL;
        cond.condition_value.data_type = FWP_SID;
        cond.condition_value.value = package_sid as usize;
        add_block_filter(engine, layer, &mut cond, name)?;
    }
    Ok(())
}

fn add_app_id_blocks(engine: Handle, helper: &Path, name: &mut [u16]) -> Result<(), KernelError> {
    let wide = wide_path(helper);
    let mut blob: *mut FwpByteBlob = ptr::null_mut();
    // SAFETY: wide is a NUL-terminated existing helper path.
    let err = unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob) };
    if err != 0 || blob.is_null() {
        return Err(win32_error("FwpmGetAppIdFromFileName0", err));
    }
    let result = (|| {
        for layer in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        ] {
            let mut cond: FwpmFilterCondition0 = unsafe { mem::zeroed() };
            cond.field_key = FWPM_CONDITION_ALE_APP_ID;
            cond.match_type = FWP_MATCH_EQUAL;
            cond.condition_value.data_type = FWP_BYTE_BLOB_TYPE;
            cond.condition_value.value = blob as usize;
            add_block_filter(engine, layer, &mut cond, name)?;
        }
        Ok(())
    })();
    // SAFETY: blob came from FwpmGetAppIdFromFileName0.
    unsafe {
        let mut p = blob.cast::<core::ffi::c_void>();
        FwpmFreeMemory0(&mut p);
    }
    result
}

fn add_block_filter(
    engine: Handle,
    layer: Guid,
    cond: &mut FwpmFilterCondition0,
    name: &mut [u16],
) -> Result<(), KernelError> {
    let mut filter: FwpmFilter0 = unsafe { mem::zeroed() };
    filter.display_data.name = name.as_mut_ptr();
    filter.layer_key = layer;
    filter.num_filter_conditions = 1;
    filter.filter_condition = cond;
    filter.action.action_type = FWP_ACTION_BLOCK;
    filter.weight.data_type = FWP_UINT8;
    filter.weight.value = 15;
    let mut id = 0u64;
    // SAFETY: engine is open; filter/cond live for the call.
    let err = unsafe { FwpmFilterAdd0(engine, &filter, ptr::null_mut(), &mut id) };
    if err != 0 {
        return Err(win32_error("FwpmFilterAdd0", err));
    }
    Ok(())
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}.{}", std::process::id(), nanos)
}

fn hresult_error(op: &str, hr: i32) -> KernelError {
    KernelError::Apply(format!("{op} failed (hr {hr:#x})"))
}
