//! Compile the Windows unique-PE helper. Skipped on other targets.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=windows_net_helper.rs");
    if env::var("CARGO_CFG_TARGET_OS").ok().as_deref() != Some("windows") {
        return;
    }
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let dest = out.join("workpen-net-helper.exe");
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let status = Command::new(rustc)
        .args([
            "--edition=2024",
            "-C",
            "opt-level=s",
            "-C",
            "debuginfo=0",
            "--crate-type=bin",
            "-o",
        ])
        .arg(&dest)
        .arg(manifest.join("windows_net_helper.rs"))
        .status()
        .expect("spawn rustc for workpen-net-helper");
    assert!(
        status.success(),
        "rustc workpen-net-helper failed: {status:?}"
    );
}
