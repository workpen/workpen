//! README install pins and publish sentences track the crate manifests.
//!
//! Manifest `0.6.0` is README `version = "0.6"` and `tag = "v0.6.0"`.
//! The two strings are not the same pin.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// First `version = "..."` under `[package]`.
fn package_version(manifest: &str) -> String {
    let mut in_package = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("version") else {
            continue;
        };
        let Some(quoted) = rest.trim().strip_prefix('=') else {
            continue;
        };
        let quoted = quoted.trim();
        let Some(inner) = quoted.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
            panic!("version is not a quoted string: {trimmed}");
        };
        return inner.to_string();
    }
    panic!("[package] version missing");
}

fn major_minor(version: &str) -> String {
    let mut parts = version.split('.');
    let major = parts.next().unwrap_or("");
    let minor = parts.next().unwrap_or("");
    assert!(
        !major.is_empty() && !minor.is_empty(),
        "version {version} needs major.minor.patch"
    );
    format!("{major}.{minor}")
}

fn section_after<'a>(text: &'a str, heading: &str) -> &'a str {
    let start = text
        .find(heading)
        .unwrap_or_else(|| panic!("missing heading {heading}"));
    let body = &text[start + heading.len()..];
    let mut rest = body;
    while let Some(nl) = rest.find('\n') {
        let line = rest[nl + 1..].lines().next().unwrap_or("");
        let trimmed = line.trim();
        let doc = trimmed.strip_prefix("//!").unwrap_or("").trim_start();
        let heading =
            trimmed.starts_with('#') || (trimmed.starts_with("//!") && doc.starts_with('#'));
        if heading {
            let end = body.len() - rest.len() + nl;
            return &body[..end];
        }
        rest = &rest[nl + 1..];
    }
    body
}

#[test]
fn readme_pins_follow_manifest_major_minor_and_full_tag() {
    let root = repo_root();
    let lib = read(&root.join("crates/workpen/Cargo.toml"));
    let cli = read(&root.join("crates/workpen-cli/Cargo.toml"));
    let readme = read(&root.join("README.md"));
    let version = package_version(&lib);
    let cli_version = package_version(&cli);
    assert_eq!(
        version, cli_version,
        "workpen and workpen-cli versions must match"
    );
    let mm = major_minor(&version);
    let dep = format!("version = \"{mm}\"");
    let tag = format!("tag = \"v{version}\"");
    assert!(
        readme.contains(&dep),
        "README must pin {dep} from manifest {version}"
    );
    assert!(
        readme.contains(&tag),
        "README must pin {tag} from manifest {version}"
    );
    assert!(
        readme.contains("features = [\"gc\", \"nono\"]"),
        "README install snippets must keep gc and nono"
    );
    if version == "0.6.0" {
        assert!(
            !readme.contains("version = \"0.5\""),
            "README still pins 0.5"
        );
        assert!(
            !readme.contains("tag = \"v0.5.0\""),
            "README still tags v0.5.0"
        );
    }
}

#[test]
fn publish_status_names_the_manifest_and_keeps_the_release_gate() {
    let root = repo_root();
    let version = package_version(&read(&root.join("crates/workpen/Cargo.toml")));
    let files = [
        root.join("crates/workpen/src/threat_model.rs"),
        root.join("docs/threat-model.md"),
        root.join("GOVERNANCE.md"),
        root.join("ROADMAP.md"),
    ];
    for path in &files {
        let text = read(path);
        assert!(
            !text.contains("stays unpublished"),
            "{} still says unpublished",
            path.display()
        );
        assert!(
            !text.contains("0.5.0 is the published crate"),
            "{} still names 0.5.0 as the published crate",
            path.display()
        );
        assert!(
            !text.contains("publish stays off"),
            "{} still says publish stays off",
            path.display()
        );
    }
    let rustdoc = read(&root.join("crates/workpen/src/threat_model.rs"));
    let markdown = read(&root.join("docs/threat-model.md"));
    let governance = read(&root.join("GOVERNANCE.md"));
    let roadmap = read(&root.join("ROADMAP.md"));
    let on_crates = format!("{version} is on crates.io");
    let later = "later publishes still wait on a release PR";
    assert!(rustdoc.contains(&on_crates), "threat_model.rs: {on_crates}");
    assert!(rustdoc.contains(later), "threat_model.rs release gate");
    assert!(
        rustdoc.contains("1.0") && rustdoc.contains("breaking"),
        "1.0 freeze wording must stay in threat_model.rs"
    );
    assert!(markdown.contains(&on_crates) && markdown.contains(later));
    assert!(governance.contains(&on_crates) && governance.contains(later));
    assert!(roadmap.contains(&format!("{version} is the published crate")));
    assert!(roadmap.contains("Further publishes wait on a release PR"));
    assert!(roadmap.contains("1.0 freeze"));
    assert!(
        markdown.contains("launch snapshot"),
        "mkdir launch-snapshot limit must stay"
    );
}

#[test]
fn docs_rs_metadata_enables_nono_and_gc_without_default_features() {
    let root = repo_root();
    let manifest = read(&root.join("crates/workpen/Cargo.toml"));
    let docs_rs = section_after(&manifest, "[package.metadata.docs.rs]");
    assert!(
        docs_rs.contains("nono") && docs_rs.contains("gc"),
        "docs.rs metadata must enable nono and gc, got {docs_rs}"
    );
    let features = section_after(&manifest, "[features]");
    let default_line = features
        .lines()
        .find(|line| line.trim().starts_with("default"))
        .unwrap_or("");
    assert_eq!(
        default_line.trim(),
        "default = []",
        "nono and gc must stay off the default feature set"
    );
}

#[test]
fn applied_does_not_mean_omits_promises() {
    let root = repo_root();
    let markdown = read(&root.join("docs/threat-model.md"));
    let limits = section_after(&markdown, "## `KernelApply::Applied` does not mean");
    for phrase in ["glued shorts", "stdbuf", "TMPDIR"] {
        assert!(
            !limits.contains(phrase),
            "does-not-mean section still contains {phrase}"
        );
    }
    let promises = section_after(&markdown, "## Promises");
    for name in ["`timeout`", "`nohup`", "`nice`", "`time`", "`stdbuf`"] {
        assert!(promises.contains(name), "wrapper list missing {name}");
    }
    assert!(!promises.contains("are wrappers too"));
    assert!(promises.contains("TMPDIR"));
    assert!(promises.contains("TEMP"));
    assert!(promises.contains("TMP"));
    assert!(promises.contains("platform default"));
    assert!(promises.contains("glued shorts"));

    let rustdoc = read(&root.join("crates/workpen/src/threat_model.rs"));
    let rust_limits = section_after(&rustdoc, "# What `KernelApply::Applied` does not mean");
    for phrase in ["glued shorts", "stdbuf", "TMPDIR"] {
        assert!(
            !rust_limits.contains(phrase),
            "rustdoc does-not-mean still contains {phrase}"
        );
    }
}
