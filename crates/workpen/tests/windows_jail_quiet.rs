//! The Windows jail must not print success-path diagnostics.
//!
//! `windows_jail.rs` is `cfg(windows)`, so a runtime assert there never
//! runs on a Mac. This file is compiled on every host. Failure lines
//! (`skipped`, `failed`, ntstatus) stay, except
//! `allow_session_object_create`. That ACE is optional. Printing it
//! says the kernel apply failed while spawn still returns `Applied`.

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

#[test]
fn skipped_namespace_ace_is_not_printed() {
    const SOURCE: &str = include_str!("../src/wrap/windows.rs");
    let start = SOURCE
        .find("fn allow_session_object_create")
        .expect("allow_session_object_create");
    let rest = &SOURCE[start..];
    let end = rest[1..]
        .find("\nfn ")
        .map(|index| index + 1)
        .unwrap_or(rest.len());
    let body = &rest[..end];
    assert!(
        !body.contains("eprintln"),
        "a skipped namespace ACE must stay quiet. Applied must not print a kernel failure:\n{body}"
    );
}
