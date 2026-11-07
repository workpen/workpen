//! The Windows jail must not print success-path diagnostics.
//!
//! `windows_jail.rs` is `cfg(windows)`, so a runtime assert there never
//! runs on a Mac. This file is compiled on every host. Failure lines
//! (`skipped`, `failed`, ntstatus) stay; they are not in the list.

#[test]
fn windows_jail_success_path_stays_quiet() {
    const SOURCE: &str = include_str!("../src/wrap/windows.rs");
    const NEEDLES: &[&str] = &[
        "msys inherit ok",
        "npfs inherit ok",
        "npfs dacl null",
        "pipe hook ntdll",
        "token default dacl null",
        "msys dir probe ok",
        "msys user section allow",
        "msys user section absent",
        "msys bno enabled",
    ];
    for needle in NEEDLES {
        assert!(
            !SOURCE.contains(needle),
            "success-path diagnostic returned: {needle}"
        );
    }
}
