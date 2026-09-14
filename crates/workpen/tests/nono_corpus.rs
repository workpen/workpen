//! Process-jail corpus. Feature `nono`. Never grant filesystem root.
//! Does not call `KernelPolicy::apply` (irreversible). `apply_pre_exec`
//! is allowed: it only installs a child hook.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use tempfile::TempDir;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use workpen::resolve_extra_root;
use workpen::{
    AGENT_LOCK_NAME, DenyPolicy, DestDenyKind, KernelAccess, KernelApply, KernelError,
    child_env_deny_names, collect_workspace_dest_denies, is_denied_child_env, kernel_supported,
    load_agent_lock, process_jail, process_jail_with_policy, require_applied, scrub_child_command,
    spawn_after_setup, with_bash_noprofile,
};

fn workspace() -> TempDir {
    TempDir::new().expect("temp workspace")
}

#[test]
fn kernel_access_is_read_or_readwrite_only() {
    let kinds = [KernelAccess::Read, KernelAccess::ReadWrite];
    assert_eq!(kinds.len(), 2);
}

#[test]
fn kernel_apply_is_applied_or_userspace_only() {
    let kinds = [KernelApply::Applied, KernelApply::UserspaceOnly];
    assert_eq!(kinds.len(), 2);
}

#[test]
fn process_jail_dest_denies_env_and_not_readme() {
    let dir = workspace();
    fs::write(dir.path().join(".env"), "SECRET=1\n").expect("env");
    fs::write(dir.path().join("readme.md"), "ok\n").expect("readme");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    assert!(
        policy
            .grants()
            .iter()
            .any(|g| g.access == KernelAccess::ReadWrite),
        "workspace stays ReadWrite; dest-deny is a second list"
    );
    let env = policy
        .dest_denies()
        .iter()
        .find(|d| d.path.file_name().is_some_and(|n| n == ".env"))
        .expect(".env dest-deny");
    assert_eq!(env.kind, DestDenyKind::DenyGlob);
    assert!(
        env.matched.as_deref() == Some("**/.env"),
        "hosts match DestDenyKind and matched glob, got {:?}",
        env.matched
    );
    assert!(
        policy
            .dest_denies()
            .iter()
            .all(|d| d.path.file_name().is_none_or(|n| n != "readme.md")),
        "readme.md must not be dest-denied"
    );
}

#[test]
fn process_jail_dest_denies_hardlink_sibling() {
    let dir = workspace();
    fs::write(dir.path().join(".env"), "SECRET=1\n").expect("env");
    fs::hard_link(dir.path().join(".env"), dir.path().join("notes.txt")).expect("hardlink");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let notes = policy
        .dest_denies()
        .iter()
        .find(|d| d.path.file_name().is_some_and(|n| n == "notes.txt"))
        .expect("hardlink sibling dest-deny");
    assert_eq!(notes.kind, DestDenyKind::HardlinkSibling);
}

#[test]
fn with_dest_deny_paths_records_host_path() {
    let dir = workspace();
    fs::write(dir.path().join("readme.md"), "ok\n").expect("readme");
    let extra = dir.path().join("host-secret.bin");
    fs::write(&extra, "x").expect("extra");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>())
        .expect("policy")
        .with_dest_deny_paths([&extra]);
    assert!(
        policy
            .dest_denies()
            .iter()
            .any(|d| d.path == extra && d.kind == DestDenyKind::DenyGlob),
        "host dest-deny path must be on the list: {:?}",
        policy.dest_denies()
    );
}

#[test]
fn agent_lock_names_reach_kernel_dest_deny_list() {
    let dir = workspace();
    fs::write(dir.path().join("team.secret"), "x\n").expect("secret");
    fs::write(dir.path().join(AGENT_LOCK_NAME), "**/*.secret\n").expect("lock");
    let extra = load_agent_lock(dir.path()).expect("load");
    let policy = DenyPolicy::with_extra(extra);
    let jail =
        process_jail_with_policy(dir.path(), std::iter::empty::<&Path>(), &policy).expect("jail");
    assert!(
        jail.dest_denies()
            .iter()
            .any(|d| d.path.file_name().is_some_and(|n| n == "team.secret")),
        "agent.lock glob must reach KernelPolicy dest-denies: {:?}",
        jail.dest_denies()
    );
}

#[test]
fn process_jail_merges_agent_lock_dest_denies() {
    let dir = workspace();
    fs::write(dir.path().join("team.secret"), "x\n").expect("secret");
    fs::write(dir.path().join(AGENT_LOCK_NAME), "**/*.secret\n").expect("lock");
    let jail = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("jail");
    assert!(
        jail.dest_denies()
            .iter()
            .any(|d| d.path.file_name().is_some_and(|n| n == "team.secret")),
        "process_jail must merge agent.lock dest-denies: {:?}",
        jail.dest_denies()
    );
}

#[test]
fn process_jail_with_policy_default_does_not_read_agent_lock() {
    let dir = workspace();
    fs::write(dir.path().join("team.secret"), "x\n").expect("secret");
    fs::write(dir.path().join(AGENT_LOCK_NAME), "**/*.secret\n").expect("lock");
    let jail = process_jail_with_policy(
        dir.path(),
        std::iter::empty::<&Path>(),
        &DenyPolicy::default(),
    )
    .expect("jail");
    assert!(
        jail.dest_denies()
            .iter()
            .all(|d| d.path.file_name().is_none_or(|n| n != "team.secret")),
        "process_jail_with_policy default must not read agent.lock: {:?}",
        jail.dest_denies()
    );
}

#[test]
fn collect_workspace_dest_denies_honors_extra_glob() {
    let dir = workspace();
    fs::write(dir.path().join("my.secret"), "x\n").expect("secret");
    let policy = DenyPolicy::with_extra(["**/*.secret".into()]);
    let found = collect_workspace_dest_denies(dir.path(), &policy).expect("collect");
    assert!(
        found.iter().any(|d| {
            d.path.file_name().is_some_and(|n| n == "my.secret") && d.kind == DestDenyKind::DenyGlob
        }),
        "extra glob must reach the kernel dest-deny list: {found:?}"
    );
    let jail =
        process_jail_with_policy(dir.path(), std::iter::empty::<&Path>(), &policy).expect("jail");
    assert!(
        jail.dest_denies()
            .iter()
            .any(|d| d.path.file_name().is_some_and(|n| n == "my.secret")),
        "process_jail_with_policy must use the host policy"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn run_child_cannot_read_workspace_env_linux() {
    if !kernel_supported() {
        return;
    }
    let dir = workspace();
    fs::write(dir.path().join(".env"), "SECRET=1\n").expect("env");
    fs::write(dir.path().join("readme.md"), "ok\n").expect("readme");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut deny_cmd = Command::new("/bin/sh");
    deny_cmd
        .args(["-c", "cat .env >env.out; echo $? >env.code"])
        .current_dir(dir.path());
    let (applied, status) = policy.run_child(deny_cmd).expect("run_child env");
    assert_eq!(applied, KernelApply::Applied);
    assert!(status.success(), "wrapper must finish: {status:?}");
    let leaked = fs::read_to_string(dir.path().join("env.out")).unwrap_or_default();
    if leaked.contains("SECRET") {
        // Unprivileged user ns denied; remount skipped, Landlock still applied.
        return;
    }
    let code = fs::read_to_string(dir.path().join("env.code")).expect("env.code");
    assert_ne!(code.trim(), "0", "cat .env must fail after remount");
    let leaked = fs::read_to_string(dir.path().join("env.out")).unwrap_or_default();
    assert!(
        !leaked.contains("SECRET"),
        "jailed child must not read .env: {leaked:?}"
    );
    let mut allow_cmd = Command::new("/bin/sh");
    allow_cmd
        .args(["-c", "cat readme.md >readme.out; echo $? >readme.code"])
        .current_dir(dir.path());
    let (_applied, status) = policy.run_child(allow_cmd).expect("readme");
    assert!(status.success(), "readme wrapper must finish: {status:?}");
    let code = fs::read_to_string(dir.path().join("readme.code")).expect("readme.code");
    assert_eq!(code.trim(), "0", "cat readme.md must succeed");
}

#[cfg(target_os = "macos")]
#[test]
fn run_child_cannot_read_env_created_after_spawn() {
    if !kernel_supported() {
        return;
    }
    let dir = workspace();
    fs::write(dir.path().join("readme.md"), "ok\n").expect("readme");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = Command::new("/bin/sh");
    cmd.args([
        "-c",
        "printf 'SECRET=1\\n' > .env; echo $? >w.code; cat .env >r.out; echo $? >r.code",
    ])
    .current_dir(dir.path());
    let (applied, status) = policy.run_child(cmd).expect("run_child");
    assert_eq!(applied, KernelApply::Applied);
    assert!(status.success(), "wrapper must finish: {status:?}");
    let write_code = fs::read_to_string(dir.path().join("w.code")).unwrap_or_default();
    let read_code = fs::read_to_string(dir.path().join("r.code")).unwrap_or_default();
    let leaked = fs::read_to_string(dir.path().join("r.out")).unwrap_or_default();
    assert!(
        write_code.trim() != "0" || read_code.trim() != "0",
        "create or read of post-spawn .env must fail, write={write_code:?} read={read_code:?}"
    );
    assert!(
        !leaked.contains("SECRET"),
        "post-create .env must not leak: {leaked:?}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn run_child_cannot_read_workspace_env() {
    if !kernel_supported() {
        return;
    }
    let dir = workspace();
    fs::write(dir.path().join(".env"), "SECRET=1\n").expect("env");
    fs::write(dir.path().join("readme.md"), "ok\n").expect("readme");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    assert!(
        policy
            .dest_denies()
            .iter()
            .any(|d| d.path.file_name().is_some_and(|n| n == ".env")),
        "list API must include .env before Seatbelt apply"
    );
    let mut deny_cmd = Command::new("/bin/sh");
    deny_cmd
        .args(["-c", "cat .env >env.out; echo $? >env.code"])
        .current_dir(dir.path());
    let (applied, status) = policy.run_child(deny_cmd).expect("run_child env");
    assert_eq!(applied, KernelApply::Applied);
    assert!(status.success(), "wrapper must finish: {status:?}");
    let code = fs::read_to_string(dir.path().join("env.code")).expect("env.code");
    assert_ne!(code.trim(), "0", "cat .env must fail under Seatbelt");
    let leaked = fs::read_to_string(dir.path().join("env.out")).unwrap_or_default();
    assert!(
        !leaked.contains("SECRET"),
        "jailed child must not read .env: {leaked:?}"
    );

    let mut allow_cmd = Command::new("/bin/sh");
    allow_cmd
        .args(["-c", "cat readme.md >readme.out; echo $? >readme.code"])
        .current_dir(dir.path());
    let (_applied, status) = policy.run_child(allow_cmd).expect("run_child readme");
    assert!(status.success(), "readme wrapper must finish: {status:?}");
    let code = fs::read_to_string(dir.path().join("readme.code")).expect("readme.code");
    assert_eq!(code.trim(), "0", "cat readme.md must succeed");
    let body = fs::read_to_string(dir.path().join("readme.out")).expect("readme.out");
    assert!(body.contains("ok"), "readme body={body:?}");
}

#[cfg(target_os = "macos")]
#[test]
fn run_child_cannot_read_env_hardlink_sibling() {
    if !kernel_supported() {
        return;
    }
    let dir = workspace();
    fs::write(dir.path().join(".env"), "SECRET=1\n").expect("env");
    fs::hard_link(dir.path().join(".env"), dir.path().join("notes.txt")).expect("hardlink");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "cat notes.txt >notes.out; echo $? >notes.code"])
        .current_dir(dir.path());
    let (applied, status) = policy.run_child(cmd).expect("run_child notes");
    assert_eq!(applied, KernelApply::Applied);
    assert!(status.success(), "wrapper must finish: {status:?}");
    let code = fs::read_to_string(dir.path().join("notes.code")).expect("notes.code");
    assert_ne!(code.trim(), "0", "cat notes.txt hardlink must fail");
    let leaked = fs::read_to_string(dir.path().join("notes.out")).unwrap_or_default();
    assert!(
        !leaked.contains("SECRET"),
        "hardlink sibling must be dest-denied: {leaked:?}"
    );
}

#[cfg(unix)]
#[test]
fn dest_deny_walk_skips_directory_symlink() {
    let dir = workspace();
    let outside = TempDir::new().expect("outside");
    fs::write(outside.path().join(".env"), "SECRET=1\n").expect("outside env");
    std::os::unix::fs::symlink(outside.path(), dir.path().join("out")).expect("symlink");
    let found = collect_workspace_dest_denies(dir.path(), &DenyPolicy::default()).expect("walk");
    assert!(
        found.iter().all(|d| !d.path.starts_with(outside.path())),
        "must not follow dir symlink to outside dest-deny: {found:?}"
    );
}

#[test]
fn workspace_is_readwrite() {
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let root = fs::canonicalize(dir.path()).expect("canon");
    let grant = policy
        .grants()
        .iter()
        .find(|g| g.path == root)
        .expect("workspace grant");
    assert_eq!(grant.access, KernelAccess::ReadWrite);
    assert!(policy.network_blocked());
}

#[test]
fn extra_root_is_readwrite() {
    let dir = workspace();
    let extra = TempDir::new().expect("extra");
    let policy = process_jail(dir.path(), [extra.path()]).expect("policy");
    let extra_root = fs::canonicalize(extra.path()).expect("canon");
    let grant = policy
        .grants()
        .iter()
        .find(|g| g.path == extra_root)
        .expect("extra grant");
    assert_eq!(grant.access, KernelAccess::ReadWrite);
}

#[cfg(target_os = "macos")]
#[test]
fn extra_root_tmp_grants_presented_and_canonical() {
    let tmp = Path::new("/tmp");
    if !tmp.is_dir() {
        return;
    }
    let Ok(canon) = fs::canonicalize(tmp) else {
        return;
    };
    let dir = workspace();
    let policy = process_jail(dir.path(), [tmp]).expect("policy");
    let presented = policy
        .grants()
        .iter()
        .find(|g| g.path == tmp)
        .expect("presented /tmp grant");
    assert_eq!(presented.access, KernelAccess::ReadWrite);
    let resolved = policy
        .grants()
        .iter()
        .find(|g| g.path == canon)
        .expect("canonical /tmp grant");
    assert_eq!(resolved.access, KernelAccess::ReadWrite);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn process_jail_grants_presented_tmp_after_resolve_extra_root() {
    let tmp = Path::new("/tmp");
    if !tmp.is_dir() {
        return;
    }
    let dir = workspace();
    let canon = resolve_extra_root(dir.path(), "/tmp").expect("explicit /tmp");
    let policy = process_jail(dir.path(), [tmp]).expect("policy");
    let presented = policy
        .grants()
        .iter()
        .find(|g| g.path == tmp)
        .unwrap_or_else(|| {
            panic!(
                "presented /tmp grant after resolve_extra_root -> {}",
                canon.display()
            )
        });
    assert_eq!(presented.access, KernelAccess::ReadWrite);
}

#[test]
fn never_grants_filesystem_root() {
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    for grant in policy.grants() {
        assert!(
            grant.path.parent().is_some() && !grant.path.parent().unwrap().as_os_str().is_empty(),
            "grant must not be filesystem root: {}",
            grant.path.display()
        );
    }
}

#[test]
fn filesystem_root_as_workspace_is_refused() {
    #[cfg(unix)]
    {
        let err = process_jail("/", std::iter::empty::<&Path>()).expect_err("root");
        assert!(matches!(err, KernelError::FsRoot(_)));
    }
    #[cfg(windows)]
    {
        let root = Path::new(r"C:\");
        if root.exists() {
            let err = process_jail(root, std::iter::empty::<&Path>()).expect_err("root");
            assert!(matches!(err, KernelError::FsRoot(_)));
        }
    }
}

#[test]
fn extra_root_filesystem_root_is_refused() {
    let dir = workspace();
    #[cfg(unix)]
    {
        let err = process_jail(dir.path(), ["/"]).expect_err("extra root");
        assert!(matches!(err, KernelError::FsRoot(_)));
    }
    #[cfg(windows)]
    {
        let root = Path::new(r"C:\");
        if root.exists() {
            let err = process_jail(dir.path(), [root]).expect_err("extra root");
            assert!(matches!(err, KernelError::FsRoot(_)));
        }
    }
}

#[test]
fn filesystem_root_error_names_path_and_subdirectory() {
    fn assert_names_path_and_next_step(err: &KernelError, refused: &Path) {
        let msg = err.to_string();
        let path = refused.display().to_string();
        assert!(
            msg.contains(&path),
            "FsRoot must name refused path {path}: {msg}"
        );
        assert!(
            msg.to_ascii_lowercase().contains("subdirectory"),
            "FsRoot must say use a subdirectory: {msg}"
        );
    }
    #[cfg(unix)]
    {
        let refused = Path::new("/");
        let err = process_jail(refused, std::iter::empty::<&Path>()).expect_err("root");
        assert_names_path_and_next_step(&err, refused);
        let extra = process_jail(workspace().path(), [refused]).expect_err("extra root");
        assert_names_path_and_next_step(&extra, refused);
    }
    #[cfg(windows)]
    {
        let refused = Path::new(r"C:\");
        if refused.exists() {
            let err = process_jail(refused, std::iter::empty::<&Path>()).expect_err("root");
            assert_names_path_and_next_step(&err, refused);
            let extra = process_jail(workspace().path(), [refused]).expect_err("extra root");
            assert_names_path_and_next_step(&extra, refused);
        }
    }
}

#[test]
fn home_as_workspace_is_refused() {
    let Some(home) = user_home_dir() else {
        return;
    };
    if !home.is_dir() {
        return;
    }
    let err = process_jail(&home, std::iter::empty::<&Path>()).expect_err("home");
    match err {
        KernelError::Home(path) => {
            let msg = KernelError::Home(path.clone()).to_string();
            assert!(
                msg.contains(&path.display().to_string()),
                "Home must name refused path: {msg}"
            );
            assert!(
                msg.to_ascii_lowercase().contains("subdirectory"),
                "Home must say use a subdirectory: {msg}"
            );
        }
        other => panic!("expected Home, got {other}"),
    }
}

#[test]
fn home_as_extra_root_is_refused() {
    let Some(home) = user_home_dir() else {
        return;
    };
    if !home.is_dir() {
        return;
    }
    let dir = workspace();
    let err = process_jail(dir.path(), [&home]).expect_err("home extra");
    match err {
        KernelError::Home(path) => {
            let msg = KernelError::Home(path.clone()).to_string();
            assert!(
                msg.contains(&path.display().to_string()),
                "Home extra must name refused path: {msg}"
            );
            assert!(
                msg.to_ascii_lowercase().contains("subdirectory"),
                "Home extra must say use a subdirectory: {msg}"
            );
        }
        other => panic!("expected Home extra, got {other}"),
    }
}

#[test]
fn temp_workspace_is_not_home() {
    let dir = workspace();
    process_jail(dir.path(), std::iter::empty::<&Path>()).expect("temp workspace");
}

#[cfg(unix)]
#[test]
fn extra_tmp_is_not_treated_as_home() {
    if !Path::new("/tmp").is_dir() {
        return;
    }
    let dir = workspace();
    process_jail(dir.path(), ["/tmp"]).expect("explicit /tmp extra");
}

fn user_home_dir() -> Option<PathBuf> {
    let raw = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    fs::canonicalize(raw).ok()
}

#[test]
fn missing_workspace_is_root_error() {
    let missing = PathBuf::from("/no-such-workpen-workspace-dir");
    let err = process_jail(&missing, std::iter::empty::<&Path>()).expect_err("missing");
    assert!(matches!(err, KernelError::Root(_)));
}

#[test]
fn existing_system_dirs_are_read() {
    let dir = workspace();
    let presented = dir.path();
    let policy = process_jail(presented, std::iter::empty::<&Path>()).expect("policy");
    let workspace = fs::canonicalize(presented).expect("canon");
    for grant in policy.grants() {
        if grant.path == workspace || grant.path == presented {
            continue;
        }
        assert_eq!(
            grant.access,
            KernelAccess::Read,
            "system grant must be Read: {}",
            grant.path.display()
        );
    }
    #[cfg(unix)]
    {
        if Path::new("/usr").is_dir() {
            let usr = fs::canonicalize("/usr").expect("usr");
            let grant = policy
                .grants()
                .iter()
                .find(|g| g.path == usr)
                .expect("/usr");
            assert_eq!(grant.access, KernelAccess::Read);
        }
    }
}

#[cfg(unix)]
#[test]
fn extra_root_overlapping_system_dir_stays_readwrite() {
    if !Path::new("/usr").is_dir() {
        return;
    }
    let dir = workspace();
    let policy = process_jail(dir.path(), ["/usr"]).expect("policy");
    let usr = fs::canonicalize("/usr").expect("usr");
    let grant = policy
        .grants()
        .iter()
        .find(|g| g.path == usr)
        .expect("/usr");
    assert_eq!(grant.access, KernelAccess::ReadWrite);
}

#[test]
fn kernel_supported_matches_os_backends() {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    assert!(kernel_supported());
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    assert!(!kernel_supported());
}

#[cfg(unix)]
#[test]
fn extra_system_read_dirs_are_granted_when_present() {
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    for candidate in ["/dev", "/etc", "/opt/homebrew", "/usr/local"] {
        let path = Path::new(candidate);
        if !path.is_dir() {
            continue;
        }
        if path.parent().is_some() && !path.parent().unwrap().as_os_str().is_empty() {
            let grant = policy
                .grants()
                .iter()
                .find(|g| g.path == path)
                .unwrap_or_else(|| panic!("missing presented system Read grant: {candidate}"));
            assert_eq!(
                grant.access,
                KernelAccess::Read,
                "presented system grant must be Read: {candidate}"
            );
        }
        let Ok(resolved) = fs::canonicalize(path) else {
            continue;
        };
        if resolved.parent().is_none()
            || resolved.parent().is_some_and(|p| p.as_os_str().is_empty())
        {
            continue;
        }
        let grant = policy
            .grants()
            .iter()
            .find(|g| g.path == resolved)
            .unwrap_or_else(|| panic!("missing canonical system Read grant: {candidate}"));
        assert_eq!(
            grant.access,
            KernelAccess::Read,
            "canonical system grant must be Read: {candidate}"
        );
    }
}

#[test]
fn apply_pre_exec_does_not_jail_the_parent() {
    let dir = workspace();
    let outside = TempDir::new().expect("outside");
    let marker = outside.path().join("parent-still-free");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = Command::new("true");
    let applied = policy.apply_pre_exec(&mut cmd).expect("pre_exec");
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert_eq!(applied, KernelApply::Applied);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    assert_eq!(applied, KernelApply::UserspaceOnly);
    fs::write(&marker, "free").expect("parent must still write outside the workspace");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn apply_pre_exec_child_can_echo() {
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = Command::new("/bin/echo");
    cmd.arg("ok");
    assert_eq!(
        policy.apply_pre_exec(&mut cmd).expect("pre_exec"),
        KernelApply::Applied
    );
    let out = cmd.output().expect("spawn child");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
}

#[test]
fn run_child_does_not_jail_the_parent() {
    let dir = workspace();
    let outside = TempDir::new().expect("outside");
    let marker = outside.path().join("parent-still-free-run-child");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = inner_true_cmd();
    cmd.current_dir(dir.path());
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        let (applied, status) = policy.run_child(cmd).expect("run_child");
        assert_eq!(applied, KernelApply::Applied);
        assert!(status.success(), "inner true/cmd must succeed: {status:?}");
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let err = policy.run_child(cmd).expect_err("no kernel backend");
        assert!(
            matches!(err, KernelError::Apply(_)),
            "unsupported OS must not spawn: {err}"
        );
    }
    fs::write(&marker, "free").expect("parent must still write outside the workspace");
}

#[cfg(unix)]
#[test]
fn run_child_timeout_kills_sleep() {
    if !kernel_supported() {
        return;
    }
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let pid_path = dir.path().join("child.pid");
    let script = format!("echo $$ > {}; exec /bin/sleep 30", pid_path.display());
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", &script]).current_dir(dir.path());
    let start = Instant::now();
    let err = policy
        .run_child_timeout(cmd, Duration::from_secs(1))
        .expect_err("timeout");
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "timeout must return in under 10s: {:?}",
        start.elapsed()
    );
    assert!(
        matches!(err, KernelError::Timeout),
        "expected Timeout, got {err}"
    );
    let pid = fs::read_to_string(&pid_path).expect("child pid");
    let pid = pid.trim();
    assert!(!pid.is_empty(), "child must have written its pid");
    let still = Command::new("/bin/kill")
        .args(["-0", pid])
        .status()
        .expect("kill -0");
    assert!(
        !still.success(),
        "child pid {pid} must be gone after timeout"
    );
}

#[cfg(windows)]
#[test]
fn run_child_timeout_kills_ping() {
    if !kernel_supported() {
        return;
    }
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = Command::new("ping");
    cmd.args(["-n", "30", "127.0.0.1"]).current_dir(dir.path());
    let start = Instant::now();
    let err = policy
        .run_child_timeout(cmd, Duration::from_secs(1))
        .expect_err("timeout");
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "timeout must return in under 10s: {:?}",
        start.elapsed()
    );
    assert!(
        matches!(err, KernelError::Timeout),
        "expected Timeout, got {err}"
    );
}

#[test]
fn run_child_timeout_fast_command_succeeds() {
    if !kernel_supported() {
        return;
    }
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = inner_true_cmd();
    cmd.current_dir(dir.path());
    let (applied, status) = policy
        .run_child_timeout(cmd, Duration::from_secs(5))
        .expect("fast command");
    assert_eq!(applied, KernelApply::Applied);
    assert!(status.success(), "fast command must succeed: {status:?}");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn run_child_cannot_write_outside_workspace() {
    let dir = workspace();
    let outside = TempDir::new().expect("outside");
    let marker = outside.path().join("should-not-exist");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let script = format!("echo x > {}", marker.display());
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", &script]).current_dir(dir.path());
    let (applied, _) = policy.run_child(cmd).expect("run_child");
    assert_eq!(applied, KernelApply::Applied);
    assert!(
        !marker.exists(),
        "child wrote outside workspace at {}",
        marker.display()
    );
}

#[cfg(windows)]
#[test]
fn run_child_cannot_write_outside_workspace() {
    let dir = workspace();
    let outside = TempDir::new().expect("outside");
    let marker = outside.path().join("should-not-exist");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = Command::new(windows_comspec());
    cmd.args(["/C", &format!("echo x 1>{}", marker.display())])
        .current_dir(dir.path());
    let (applied, _) = policy.run_child(cmd).expect("run_child");
    assert_eq!(applied, KernelApply::Applied);
    assert!(
        !marker.exists(),
        "child wrote outside workspace at {}",
        marker.display()
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn run_child_can_write_inside_workspace() {
    let dir = workspace();
    let inside = dir.path().join("inside.txt");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "echo ok > inside.txt"])
        .current_dir(dir.path());
    let (applied, status) = policy.run_child(cmd).expect("run_child");
    assert_eq!(applied, KernelApply::Applied);
    assert!(status.success(), "inside write must succeed: {status:?}");
    let body = fs::read_to_string(&inside).expect("inside write");
    assert!(body.contains("ok"), "inside body={body:?}");
}

#[cfg(windows)]
#[test]
fn run_child_can_write_inside_workspace() {
    let dir = workspace();
    let inside = dir.path().join("inside.txt");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = Command::new(windows_comspec());
    cmd.args(["/C", "echo ok 1>inside.txt"])
        .current_dir(dir.path());
    let (applied, status) = policy.run_child(cmd).expect("run_child");
    assert_eq!(applied, KernelApply::Applied);
    assert!(status.success(), "inside write must succeed: {status:?}");
    let body = fs::read_to_string(&inside).expect("inside write");
    assert!(body.contains("ok"), "inside body={body:?}");
}

#[cfg(windows)]
#[test]
fn run_child_cannot_read_workspace_env_windows() {
    if !kernel_supported() {
        return;
    }
    let dir = workspace();
    fs::write(dir.path().join(".env"), "SECRET=1\n").expect("env");
    fs::write(dir.path().join("readme.md"), "ok\n").expect("readme");
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut deny_cmd = Command::new(windows_comspec());
    deny_cmd
        .args(["/C", "type .env 1>env.out & echo %ERRORLEVEL% 1>env.code"])
        .current_dir(dir.path());
    let (applied, status) = policy.run_child(deny_cmd).expect("run_child env");
    assert_eq!(applied, KernelApply::Applied);
    assert!(status.success(), "wrapper must finish: {status:?}");
    let leaked = fs::read_to_string(dir.path().join("env.out")).unwrap_or_default();
    assert!(
        !leaked.contains("SECRET"),
        "jailed child must not read .env: {leaked:?}"
    );
    let mut allow_cmd = Command::new(windows_comspec());
    allow_cmd
        .args(["/C", "type readme.md 1>readme.out"])
        .current_dir(dir.path());
    let (_applied, status) = policy.run_child(allow_cmd).expect("readme");
    assert!(status.success(), "readme wrapper must finish: {status:?}");
    let body = fs::read_to_string(dir.path().join("readme.out")).expect("readme.out");
    assert!(body.contains("ok"), "readme body={body:?}");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn run_child_network_blocked_tcp_fails() {
    if !kernel_supported() {
        return;
    }
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    assert!(
        policy.network_blocked(),
        "process_jail must ask the kernel to block sockets"
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
    let port = listener.local_addr().expect("addr").port();
    let script = format!("echo >/dev/tcp/127.0.0.1/{port}");
    let mut cmd = Command::new("/bin/bash");
    cmd.args(["-c", &script]).current_dir(dir.path());
    let (applied, status) = policy.run_child(cmd).expect("run_child");
    assert_eq!(applied, KernelApply::Applied);
    assert!(
        !status.success(),
        "jailed child must not open TCP to 127.0.0.1:{port}: {status:?}"
    );
}

fn inner_true_cmd() -> Command {
    #[cfg(windows)]
    {
        let mut cmd = Command::new(windows_comspec());
        cmd.args(["/C", "exit 0"]);
        cmd
    }
    #[cfg(not(windows))]
    {
        Command::new("true")
    }
}

#[cfg(windows)]
fn windows_comspec() -> std::ffi::OsString {
    std::env::var_os("COMSPEC").unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".into())
}

#[test]
fn run_inserts_noprofile_norc_for_bash_argv0() {
    for program in [
        "bash",
        "/usr/bin/bash",
        r"C:\Program Files\Git\bin\bash.exe",
        "BASH.EXE",
    ] {
        let (got, args) = with_bash_noprofile(program, ["-c", "echo ok"]);
        assert_eq!(got, program);
        assert_eq!(
            args,
            ["--noprofile", "--norc", "-c", "echo ok"],
            "bash argv0 {program}"
        );
    }
    let (got, args) = with_bash_noprofile("bash", [] as [&str; 0]);
    assert_eq!(got, "bash");
    assert_eq!(args, ["--noprofile", "--norc"]);
}

#[test]
fn run_leaves_cmd_exe_argv_unchanged() {
    for program in ["cmd.exe", "/bin/sh", "pwsh", "git", "rbash"] {
        let (got, args) = with_bash_noprofile(program, ["/C", "echo ok"]);
        assert_eq!(got, program);
        assert_eq!(args, ["/C", "echo ok"], "non-bash argv0 {program}");
    }
    let (got, args) = with_bash_noprofile("env", ["/C", "echo ok"]);
    assert_eq!(got, "env");
    assert_eq!(args, ["/C", "echo ok"], "env operand that is not bash");
}

#[test]
fn run_inserts_noprofile_norc_after_env_bash_operand() {
    for program in ["env", "/usr/bin/env", r"C:\Windows\System32\env.exe", "ENV"] {
        let (got, args) = with_bash_noprofile(program, ["bash", "-l", "-c", "true"]);
        assert_eq!(got, program);
        assert_eq!(
            args,
            ["bash", "--noprofile", "--norc", "-l", "-c", "true"],
            "env argv0 {program}"
        );
    }
    let (got, args) = with_bash_noprofile("env.exe", ["bash.exe", "-c", "true"]);
    assert_eq!(got, "env.exe");
    assert_eq!(args, ["bash.exe", "--noprofile", "--norc", "-c", "true"]);
    let (_got, args) =
        with_bash_noprofile("/usr/bin/env", ["-i", "-u", "FOO", "bash", "-c", "true"]);
    assert_eq!(
        args,
        [
            "-i",
            "-u",
            "FOO",
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            "true"
        ]
    );
    let (_got, args) = with_bash_noprofile("env", ["-S", "bash -c true"]);
    assert_eq!(args, ["-S", "bash -c true"], "env -S takes the next token");
    let (_got, args) = with_bash_noprofile("env", ["python", "-c", "true"]);
    assert_eq!(args, ["python", "-c", "true"], "env python is not bash");
    let (_got, args) = with_bash_noprofile("env", ["bash", "--noprofile", "-c", "true"]);
    assert_eq!(args, ["bash", "--noprofile", "--norc", "-c", "true"]);
}

#[test]
fn run_inserts_noprofile_norc_after_clustered_env_flags() {
    let (_got, args) = with_bash_noprofile("env", ["-iC", "/tmp", "bash", "-c", "true"]);
    assert_eq!(
        args,
        ["-iC", "/tmp", "bash", "--noprofile", "--norc", "-c", "true"],
        "env -iC /tmp bash must skip /tmp as -C operand"
    );
    let (_got, args) = with_bash_noprofile("env", ["-f", "dotenv", "bash", "-c", "true"]);
    assert_eq!(
        args,
        [
            "-f",
            "dotenv",
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            "true"
        ],
        "env -f dotenv bash must skip dotenv as -f operand"
    );
    let (_got, args) = with_bash_noprofile("env", ["--file", "dotenv", "bash", "-c", "true"]);
    assert_eq!(
        args,
        [
            "--file",
            "dotenv",
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            "true"
        ],
        "env --file dotenv bash must skip dotenv as --file operand"
    );
    let (_got, args) = with_bash_noprofile("env", ["-C/tmp", "bash", "-c", "true"]);
    assert_eq!(
        args,
        ["-C/tmp", "bash", "--noprofile", "--norc", "-c", "true"],
        "attached -C/tmp stays skip 1"
    );
    let (_got, args) = with_bash_noprofile("env", ["--file=.env", "bash", "-c", "true"]);
    assert_eq!(
        args,
        ["--file=.env", "bash", "--noprofile", "--norc", "-c", "true"],
        "attached --file=.env stays skip 1"
    );
    let (_got, args) = with_bash_noprofile("env", ["-vSbash", "-c", "true"]);
    assert_eq!(
        args,
        ["-vSbash", "-c", "true"],
        "attached -vSbash stays skip 1 and is not argv bash"
    );
}

#[test]
fn with_bash_noprofile_drops_denied_env_assignments() {
    let (_got, args) = with_bash_noprofile(
        "env",
        ["BASH_ENV=.env", "bash", "-c", r#"printf %s "$BASH_ENV""#],
    );
    assert!(
        !args.iter().any(|a| {
            a.to_string_lossy()
                .split_once('=')
                .is_some_and(|(n, _)| n.eq_ignore_ascii_case("BASH_ENV"))
        }),
        "denied BASH_ENV assignment must be dropped: {args:?}"
    );
    assert_eq!(
        args,
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            r#"printf %s "$BASH_ENV""#
        ]
    );
    let (_got, args) = with_bash_noprofile(
        "/usr/bin/env",
        [
            "FOO=bar",
            "LD_PRELOAD=./x.so",
            "PATH=/bin",
            "bash",
            "-c",
            "true",
        ],
    );
    assert_eq!(
        args,
        [
            "FOO=bar",
            "PATH=/bin",
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            "true"
        ],
        "denylist assignments drop; other NAME=value stay"
    );
    let (_got, args) = with_bash_noprofile("env.exe", ["bash_env=.env", "python", "-c", "true"]);
    assert_eq!(
        args,
        ["python", "-c", "true"],
        "case-insensitive denylist drop without rewriting non-bash"
    );
}

#[test]
fn with_bash_noprofile_drops_denied_assignments_inside_env_s() {
    let (_got, args) = with_bash_noprofile("env", ["-S", "BASH_ENV=.env", "bash", "-c", "true"]);
    assert!(
        !args.iter().any(|a| {
            a.to_string_lossy()
                .split_once('=')
                .is_some_and(|(n, _)| n.eq_ignore_ascii_case("BASH_ENV"))
        }),
        "denied BASH_ENV inside env -S must be dropped: {args:?}"
    );
    assert_eq!(
        args,
        ["-S", "", "bash", "--noprofile", "--norc", "-c", "true"]
    );
    let (_got, args) = with_bash_noprofile("env", ["-S", "FOO=bar BASH_ENV=.env bash -c true"]);
    assert_eq!(
        args,
        ["-S", "FOO=bar bash -c true"],
        "denylist drop inside -S leftover; other tokens stay"
    );
    let (_got, args) = with_bash_noprofile(
        "env",
        ["--split-string=BASH_ENV=.env", "python", "-c", "true"],
    );
    assert_eq!(
        args,
        ["--split-string=", "python", "-c", "true"],
        "attached --split-string denylist assignment must drop"
    );
    let (_got, args) = with_bash_noprofile("env", ["-S", "--file=readme.md", "bash", "-c", "true"]);
    assert_eq!(
        args,
        [
            "-S",
            "--file=readme.md",
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            "true"
        ],
        "env -S --file=readme.md leftover flag is not an assignment drop"
    );
}

#[test]
fn run_inserts_noprofile_norc_after_timeout_nohup_nice_bash() {
    for program in [
        "timeout",
        "/usr/bin/timeout",
        r"C:\Windows\System32\timeout.exe",
        "TIMEOUT.EXE",
    ] {
        let (got, args) = with_bash_noprofile(program, ["30", "bash", "-l", "-c", "true"]);
        assert_eq!(got, program);
        assert_eq!(
            args,
            ["30", "bash", "--noprofile", "--norc", "-l", "-c", "true"],
            "timeout argv0 {program}"
        );
    }
    for program in ["nohup", "/usr/bin/nohup", "NOHUP.EXE"] {
        let (got, args) = with_bash_noprofile(program, ["bash", "-l", "-c", "true"]);
        assert_eq!(got, program);
        assert_eq!(
            args,
            ["bash", "--noprofile", "--norc", "-l", "-c", "true"],
            "nohup argv0 {program}"
        );
    }
    for program in ["nice", "/usr/bin/nice", "NICE.EXE"] {
        let (got, args) = with_bash_noprofile(program, ["bash", "-l", "-c", "true"]);
        assert_eq!(got, program);
        assert_eq!(
            args,
            ["bash", "--noprofile", "--norc", "-l", "-c", "true"],
            "nice argv0 {program}"
        );
    }
    let (_got, args) = with_bash_noprofile("timeout", ["30", "echo", "hi"]);
    assert_eq!(
        args,
        ["30", "echo", "hi"],
        "timeout 30 echo hi must not invent bash flags"
    );
    let (_got, args) = with_bash_noprofile("nice", ["-n", "10", "bash", "-l", "-c", "true"]);
    assert_eq!(
        args,
        [
            "-n",
            "10",
            "bash",
            "--noprofile",
            "--norc",
            "-l",
            "-c",
            "true"
        ],
        "nice -n 10 must skip the adjustment"
    );
    let (_got, args) = with_bash_noprofile("timeout", ["--foreground", "30", "bash", "-c", "true"]);
    assert_eq!(
        args,
        [
            "--foreground",
            "30",
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            "true"
        ],
        "timeout flags then duration then bash"
    );
    let (_got, args) = with_bash_noprofile("timeout", ["-s", "TERM", "30", "bash", "-c", "true"]);
    assert_eq!(
        args,
        [
            "-s",
            "TERM",
            "30",
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            "true"
        ],
        "timeout -s SIGNAL must skip the signal operand"
    );
}

#[test]
fn with_bash_noprofile_wrapper_then_env_bash() {
    let (_got, args) = with_bash_noprofile("timeout", ["30", "env", "bash", "-l", "-c", "true"]);
    assert_eq!(
        args,
        [
            "30",
            "env",
            "bash",
            "--noprofile",
            "--norc",
            "-l",
            "-c",
            "true"
        ],
        "timeout 30 env bash -l must insert noprofile after bash"
    );
    let (_got, args) = with_bash_noprofile(
        "timeout",
        ["30", "env", "BASH_ENV=.env", "bash", "-c", "true"],
    );
    assert!(
        !args.iter().any(|a| {
            a.to_string_lossy()
                .split_once('=')
                .is_some_and(|(n, _)| n.eq_ignore_ascii_case("BASH_ENV"))
        }),
        "timeout 30 env BASH_ENV=.env bash must drop BASH_ENV: {args:?}"
    );
    assert_eq!(
        args,
        ["30", "env", "bash", "--noprofile", "--norc", "-c", "true"]
    );
    let (_got, args) = with_bash_noprofile("nohup", ["env", "bash", "-l", "-c", "true"]);
    assert_eq!(
        args,
        ["env", "bash", "--noprofile", "--norc", "-l", "-c", "true"],
        "nohup env bash -l must insert noprofile after bash"
    );
    let (_got, args) = with_bash_noprofile("nice", ["-n", "10", "env", "bash", "-c", "true"]);
    assert_eq!(
        args,
        [
            "-n",
            "10",
            "env",
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            "true"
        ],
        "nice -n 10 env bash must skip adjustment then insert after bash"
    );
    let (_got, args) = with_bash_noprofile(
        "/usr/bin/timeout",
        [
            "--foreground",
            "30",
            "env",
            "LD_PRELOAD=./x.so",
            "bash",
            "-c",
            "true",
        ],
    );
    assert_eq!(
        args,
        [
            "--foreground",
            "30",
            "env",
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            "true"
        ],
        "timeout flags then env denylist drop then noprofile"
    );
    let (_got, args) = with_bash_noprofile("timeout", ["30", "echo", "hi"]);
    assert_eq!(
        args,
        ["30", "echo", "hi"],
        "timeout 30 echo hi must stay unchanged"
    );
    let (_got, args) = with_bash_noprofile("timeout", ["30", "cat", "readme.md"]);
    assert_eq!(
        args,
        ["30", "cat", "readme.md"],
        "timeout 30 cat readme.md must stay unchanged"
    );
    let (_got, args) = with_bash_noprofile("timeout", ["30", "env", "-S", "cat readme.md"]);
    assert_eq!(
        args,
        ["30", "env", "-S", "cat readme.md"],
        "timeout 30 env -S cat readme.md is not argv bash"
    );
}

#[test]
fn run_does_not_duplicate_existing_noprofile() {
    let (_got, args) = with_bash_noprofile("bash", ["--noprofile", "--norc", "-c", "true"]);
    assert_eq!(args, ["--noprofile", "--norc", "-c", "true"]);
    let (_got, args) = with_bash_noprofile("bash", ["--noprofile", "-c", "true"]);
    assert_eq!(args, ["--noprofile", "--norc", "-c", "true"]);
    let (_got, args) = with_bash_noprofile("bash", ["--norc", "-c", "true"]);
    assert_eq!(args, ["--noprofile", "--norc", "-c", "true"]);
}

#[test]
fn is_denied_child_env_keys_and_not_path() {
    assert!(is_denied_child_env("xai_api_key"));
    assert!(is_denied_child_env("Ld_Preload"));
    assert!(!is_denied_child_env("PATH"));
}

#[test]
fn scrub_child_command_removes_denied_names() {
    let mut cmd = Command::new("true");
    cmd.env("XAI_API_KEY", "secret")
        .env("LD_PRELOAD", "evil.so")
        .env("BASH_ENV", "/tmp/evil.sh");
    scrub_child_command(&mut cmd);
    for name in ["XAI_API_KEY", "LD_PRELOAD", "BASH_ENV"] {
        let value = cmd
            .get_envs()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value);
        assert_eq!(value, Some(None), "{name} must be removed from cmd envs");
    }
}

#[test]
fn child_env_deny_names_include_loader_and_keys() {
    let names = child_env_deny_names();
    for required in [
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "BASH_ENV",
        "ENV",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "PERL5OPT",
        "XAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
    ] {
        assert!(
            names.contains(&required),
            "denylist must include {required}: {names:?}"
        );
    }
    for keep in [
        "PATH",
        "HOME",
        "USERPROFILE",
        "SystemRoot",
        "COMSPEC",
        "TMPDIR",
        "TEMP",
    ] {
        assert!(
            !names.contains(&keep),
            "denylist must not strip {keep}: {names:?}"
        );
    }
}

fn env_defined_cmd(name: &str) -> Command {
    #[cfg(unix)]
    {
        let mut cmd = Command::new("/usr/bin/printenv");
        cmd.arg(name);
        cmd
    }
    #[cfg(windows)]
    {
        let mut cmd = Command::new(windows_comspec());
        cmd.args(["/C", &format!("if defined {name} (exit 0) else (exit 1)")]);
        cmd
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = name;
        Command::new("false")
    }
}

#[cfg(unix)]
fn printenv_available() -> bool {
    Path::new("/usr/bin/printenv").is_file()
}

#[cfg(not(unix))]
fn printenv_available() -> bool {
    true
}

#[test]
fn run_child_scrubs_ld_preload() {
    if !printenv_available() {
        return;
    }
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = env_defined_cmd("LD_PRELOAD");
    cmd.env("LD_PRELOAD", "evil.so").current_dir(dir.path());
    let (_applied, status) = policy.run_child(cmd).expect("run_child");
    assert!(
        !status.success(),
        "LD_PRELOAD must be absent after scrub: {status:?}"
    );
}

#[test]
fn run_child_scrubs_bash_env() {
    if !printenv_available() {
        return;
    }
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = env_defined_cmd("BASH_ENV");
    cmd.env("BASH_ENV", "/tmp/evil.sh").current_dir(dir.path());
    let (_applied, status) = policy.run_child(cmd).expect("run_child");
    assert!(
        !status.success(),
        "BASH_ENV must be absent after scrub: {status:?}"
    );
}

#[test]
fn run_child_scrubs_xai_api_key() {
    if !printenv_available() {
        return;
    }
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = env_defined_cmd("XAI_API_KEY");
    cmd.env("XAI_API_KEY", "secret").current_dir(dir.path());
    let (_applied, status) = policy.run_child(cmd).expect("run_child");
    assert!(
        !status.success(),
        "XAI_API_KEY must be absent after scrub: {status:?}"
    );
}

#[test]
fn run_child_keeps_path() {
    if !printenv_available() {
        return;
    }
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    let mut cmd = env_defined_cmd("PATH");
    cmd.env("PATH", "/usr/bin:/bin").current_dir(dir.path());
    let (_applied, status) = policy.run_child(cmd).expect("run_child");
    assert!(status.success(), "PATH must remain after scrub: {status:?}");
}

#[test]
fn run_child_token_err_is_apply_and_does_not_spawn() {
    let mut spawned = false;
    let err = spawn_after_setup(
        Err::<(), _>(KernelError::Apply("token setup failed".into())),
        |_| {
            spawned = true;
            panic!("must not spawn after token setup Err");
        },
    )
    .expect_err("token Err must refuse spawn");
    match err {
        KernelError::Apply(msg) => {
            assert!(msg.contains("token"), "error must name token: {msg}");
        }
        other => panic!("expected Apply, got {other}"),
    }
    assert!(!spawned, "spawn must not run after token Err");
}

#[test]
fn run_child_job_err_is_apply_and_does_not_spawn() {
    let mut spawned = false;
    let err = spawn_after_setup(
        Err::<(), _>(KernelError::Apply("job setup failed".into())),
        |_| {
            spawned = true;
            panic!("must not spawn after job setup Err");
        },
    )
    .expect_err("job Err must refuse spawn");
    match err {
        KernelError::Apply(msg) => {
            assert!(msg.contains("job"), "error must name job: {msg}");
        }
        other => panic!("expected Apply, got {other}"),
    }
    assert!(!spawned, "spawn must not run after job Err");
}

#[test]
fn require_applied_userspace_only_is_apply_and_does_not_spawn() {
    let mut spawned = false;
    let err = spawn_after_setup(require_applied(KernelApply::UserspaceOnly), |_| {
        spawned = true;
        panic!("must not spawn after UserspaceOnly");
    })
    .expect_err("UserspaceOnly must refuse spawn");
    match err {
        KernelError::Apply(msg) => {
            assert!(
                msg.contains("did not apply"),
                "error must say jail did not apply: {msg}"
            );
            assert!(
                msg.contains("not started"),
                "error must say child was not started: {msg}"
            );
        }
        other => panic!("expected Apply, got {other}"),
    }
    assert!(!spawned, "spawn must not run after UserspaceOnly");
}

#[test]
fn require_applied_keeps_applied() {
    assert_eq!(
        require_applied(KernelApply::Applied).expect("Applied"),
        KernelApply::Applied
    );
}

#[test]
fn apply_inspect_stays_userspace_only_when_kernel_unsupported() {
    if kernel_supported() {
        return;
    }
    let dir = workspace();
    let policy = process_jail(dir.path(), std::iter::empty::<&Path>()).expect("policy");
    assert_eq!(
        policy.apply().expect("apply inspect"),
        KernelApply::UserspaceOnly
    );
    let mut cmd = inner_true_cmd();
    assert_eq!(
        policy.apply_pre_exec(&mut cmd).expect("pre_exec inspect"),
        KernelApply::UserspaceOnly
    );
    let err = policy.run_child(inner_true_cmd()).expect_err("run_child");
    assert!(
        matches!(err, KernelError::Apply(_)),
        "run_child must fail closed when kernel is unsupported: {err}"
    );
    let err = policy
        .run_child_timeout(inner_true_cmd(), Duration::from_secs(5))
        .expect_err("run_child_timeout");
    assert!(
        matches!(err, KernelError::Apply(_)),
        "run_child_timeout must fail closed when kernel is unsupported: {err}"
    );
}
