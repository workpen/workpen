//! Process-jail corpus. Feature `nono`. Never grant filesystem root.
//! Does not call `KernelPolicy::apply` (irreversible). `apply_pre_exec`
//! is allowed: it only installs a child hook.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;
use workpen::{
    KernelAccess, KernelApply, KernelError, child_env_deny_names, is_denied_child_env,
    kernel_supported, process_jail, resolve_extra_root, scrub_child_command, spawn_after_setup,
    with_bash_noprofile,
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
    let (applied, status) = policy.run_child(cmd).expect("run_child");
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    assert_eq!(applied, KernelApply::Applied);
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    assert_eq!(applied, KernelApply::UserspaceOnly);
    assert!(status.success(), "inner true/cmd must succeed: {status:?}");
    fs::write(&marker, "free").expect("parent must still write outside the workspace");
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
