//! Dest-deny corpus. Typechecks against the public API. Predicate asserts
//! stay red until the classify / argv / glob implementations land.

use std::path::Path;

use workpen::{
    CheckDestError, DenyPolicy, DestDeny, DestDenyError, DestDenyKind, PathGuard,
    check_command_argv, check_command_dests, check_dest, classify_dest, default_secret_denies,
    deny_patch_dests, deny_patch_dests_with_display, dest_deny_message, is_env_template_basename,
    is_path_denied, open_verified_read, path_is_denied_glob, reject_command_secret_path_tokens,
    verify_post_open,
};

#[test]
fn default_secret_denies_matches_bline_v1_list() {
    let got = default_secret_denies();
    let want = [
        "**/.env",
        "**/.env.*",
        "**/*.pem",
        "**/*.key",
        "**/*.p12",
        "**/*.pfx",
        "**/id_rsa",
        "**/id_ed25519",
        "**/id_ecdsa",
        "**/id_dsa",
        "**/id_eddsa",
        "**/.npmrc",
        "**/.pypirc",
        "**/.docker/config.json",
        "**/kubeconfig",
        "**/.kube/config",
        "**/secrets.json",
        "**/service-account*.json",
        "**/.ssh/**",
        "**/token.json",
        "**/secring.gpg",
        "**/.gnupg/private-keys-v1.d/**",
        "**/credentials.json",
        "**/.aws/credentials",
        "**/.netrc",
        "**/secrets/**",
        "**/credentials/**",
        "**/gateway/pairing.json",
        "**/auth.json",
        "**/auth-*.json",
    ];
    assert_eq!(got, want);
    assert!(
        !got.iter()
            .any(|g| g.contains(".azure") || g.contains(".config/gh")),
        "home-relative Windows dirs are not userspace globs: {got:?}"
    );
}

#[test]
fn dest_deny_kind_is_glob_or_hardlink_only() {
    match DestDenyKind::DenyGlob {
        DestDenyKind::DenyGlob | DestDenyKind::HardlinkSibling => {}
    }
}

#[test]
fn dest_deny_message_wording_splits_glob_and_hardlink() {
    let glob = DestDeny {
        kind: DestDenyKind::DenyGlob,
        path: Path::new(".env").to_path_buf(),
        display: ".env".into(),
        matched: None,
    };
    let glob_msg = glob.message().to_ascii_lowercase();
    assert!(glob_msg.contains("matches deny glob"), "{glob_msg}");
    assert!(
        !glob_msg.contains("hardlink of a denied name"),
        "{glob_msg}"
    );

    let link = DestDeny {
        kind: DestDenyKind::HardlinkSibling,
        path: Path::new("notes.txt").to_path_buf(),
        display: "notes.txt".into(),
        matched: None,
    };
    let link_msg = link.message().to_ascii_lowercase();
    assert!(link_msg.contains("hardlink"), "{link_msg}");
    assert!(!link_msg.contains("matches deny glob"), "{link_msg}");
}

#[test]
fn env_template_basename_carve_out() {
    assert!(is_env_template_basename(".env.example"));
    assert!(is_env_template_basename("proj/.env.sample"));
    assert!(is_env_template_basename(".ENV.template"));
    assert!(!is_env_template_basename(".env"));
    assert!(!is_env_template_basename(".env.local"));
    assert!(!is_env_template_basename(".env.production"));
}

#[test]
fn extra_glob_can_dest_deny_env_template() {
    let policy = DenyPolicy::with_extra(["**/.env.example".into()]);
    assert!(
        is_path_denied(Path::new(".env.example"), &policy),
        "extra glob must dest-deny .env.example"
    );
    assert!(
        is_path_denied(Path::new("proj/.env.example"), &policy),
        "extra glob must dest-deny nested .env.example"
    );
    let defaults = DenyPolicy::default();
    assert!(!is_path_denied(Path::new(".env.example"), &defaults));
    assert!(!is_path_denied(Path::new(".env.sample"), &defaults));
    assert!(!is_path_denied(Path::new(".env.template"), &defaults));
    assert!(!is_path_denied(Path::new(".ENV.example"), &defaults));
    assert!(is_path_denied(Path::new(".env.local"), &defaults));
}

#[test]
fn is_path_denied_env_ssh_source_and_pairing_names() {
    let policy = DenyPolicy::default();
    assert!(is_path_denied(Path::new(".env"), &policy));
    assert!(is_path_denied(Path::new("home/.ssh/id_ed25519"), &policy));
    assert!(is_path_denied(
        Path::new("proj/gateway/pairing.json"),
        &policy
    ));
    assert!(is_path_denied(Path::new("auth.json"), &policy));
    assert!(is_path_denied(Path::new("auth-work.json"), &policy));
    assert!(!is_path_denied(Path::new("src/lib.rs"), &policy));
}

#[cfg(unix)]
#[test]
fn is_path_denied_follows_symlink_to_env() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join(".env");
    std::fs::write(&env, "SECRET=1\n").expect("write .env");
    let alias = dir.path().join("config");
    std::os::unix::fs::symlink(&env, &alias).expect("symlink");
    let policy = DenyPolicy::default();
    assert!(
        is_path_denied(&alias, &policy),
        "symlink named config -> .env must be denied"
    );
    assert!(!is_path_denied(&dir.path().join("readme.md"), &policy));
}

#[test]
fn is_path_denied_same_inode_hardlink_sibling_of_env() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join(".env");
    std::fs::write(&env, "API_KEY=secret\n").expect("write .env");
    let sibling = dir.path().join("sibling.txt");
    std::fs::hard_link(&env, &sibling).expect("hardlink");
    let policy = DenyPolicy::default();
    assert!(is_path_denied(&env, &policy), ".env name still denied");
    assert!(
        is_path_denied(&sibling, &policy),
        "same-inode sibling.txt of .env must be denied"
    );
    let innocent = dir.path().join("readme.md");
    std::fs::write(&innocent, "ok\n").expect("write readme");
    let innocent_link = dir.path().join("readme-copy.md");
    std::fs::hard_link(&innocent, &innocent_link).expect("innocent hardlink");
    assert!(
        !is_path_denied(&innocent_link, &policy),
        "hardlink of a non-secret file must still be allowed"
    );
}

#[test]
fn dest_deny_message_reports_hardlink_not_glob_for_sibling() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join(".env");
    std::fs::write(&env, "API_KEY=secret\n").expect("write .env");
    let sibling = dir.path().join("notes.txt");
    std::fs::hard_link(&env, &sibling).expect("hardlink");
    let policy = DenyPolicy::default();
    let msg = dest_deny_message(&sibling, &sibling.to_string_lossy(), &policy)
        .expect("sibling must dest-deny")
        .to_ascii_lowercase();
    assert!(
        msg.contains("sandbox profile") && msg.contains("hardlink"),
        "{msg}"
    );
    assert!(!msg.contains("unlink extra names"), "{msg}");
    assert!(!msg.contains("matches deny glob"), "{msg}");
    assert!(
        msg.contains(".env"),
        "hardlink dest-deny must name the denied sibling: {msg}"
    );
    let glob_msg = dest_deny_message(&env, &env.to_string_lossy(), &policy)
        .expect(".env is a deny glob")
        .to_ascii_lowercase();
    assert!(glob_msg.contains("matches deny glob"), "{glob_msg}");
    assert!(
        glob_msg.contains("**/.env"),
        "glob dest-deny must name the matching glob: {glob_msg}"
    );
}

#[test]
fn dest_deny_message_names_auth_star_glob() {
    let policy = DenyPolicy::default();
    let msg = dest_deny_message(Path::new("auth-work.json"), "auth-work.json", &policy)
        .expect("auth-work.json must dest-deny");
    let lower = msg.to_ascii_lowercase();
    assert!(lower.contains("matches deny glob"), "{msg}");
    assert!(
        msg.contains("**/auth-*.json"),
        "glob dest-deny must name **/auth-*.json: {msg}"
    );
}

#[cfg(unix)]
#[test]
fn is_path_denied_symlink_to_hardlink_sibling_of_env() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join(".env");
    std::fs::write(&env, "API_KEY=secret\n").expect("write .env");
    let config = dir.path().join("config");
    std::fs::hard_link(&env, &config).expect("hardlink");
    let notes = dir.path().join("notes.txt");
    std::os::unix::fs::symlink(&config, &notes).expect("symlink");
    let policy = DenyPolicy::default();
    assert!(
        is_path_denied(&notes, &policy),
        "symlink notes.txt -> config hardlink of .env must be denied"
    );
}

#[cfg(windows)]
#[test]
fn windows_same_inode_sibling_of_env_is_denied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join(".env");
    std::fs::write(&env, "API_KEY=secret\n").expect("write .env");
    let sibling = dir.path().join("sibling.txt");
    std::fs::hard_link(&env, &sibling).expect("hardlink");
    let policy = DenyPolicy::default();
    assert!(
        is_path_denied(&sibling, &policy),
        "FindFirstFileNameW same-inode sibling of .env must be denied"
    );
}

#[test]
fn argv_cat_env_and_plain_echo() {
    let policy = DenyPolicy::default();
    let err =
        reject_command_secret_path_tokens("cat .env", &policy).expect_err("cat .env must deny");
    match err {
        DestDenyError::CommandToken { token } => {
            assert!(token.contains(".env"), "{token}");
        }
        other => panic!("expected CommandToken, got {other}"),
    }
    reject_command_secret_path_tokens("echo hello", &policy).expect("plain echo ok");
    reject_command_secret_path_tokens("ls -la", &policy).expect("flags pass");
}

#[test]
fn argv_denies_pairing_and_auth_tokens() {
    let policy = DenyPolicy::default();
    reject_command_secret_path_tokens("cat gateway/pairing.json", &policy)
        .expect_err("relative pairing");
    reject_command_secret_path_tokens("cat /tmp/bline/gateway/pairing.json", &policy)
        .expect_err("absolute pairing");
    reject_command_secret_path_tokens("cat auth.json", &policy).expect_err("auth.json");
    reject_command_secret_path_tokens("cat auth-work.json", &policy).expect_err("auth-*.json");
    reject_command_secret_path_tokens("cat pairing.json", &policy)
        .expect("bare pairing.json is not **/gateway/pairing.json");
}

#[test]
fn argv_denies_hardlink_and_symlink_tokens() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join(".env");
    std::fs::write(&env, "API_KEY=secret\n").expect("write .env");
    let sibling = dir.path().join("notes.txt");
    std::fs::hard_link(&env, &sibling).expect("hardlink");
    let policy = DenyPolicy::default();
    let cmd = format!("cat {}", sibling.display());
    reject_command_secret_path_tokens(&cmd, &policy)
        .expect_err("argv must dest-deny hardlink sibling token");
    #[cfg(unix)]
    {
        let alias = dir.path().join("config");
        std::os::unix::fs::symlink(&env, &alias).expect("symlink");
        let cmd = format!("cat {}", alias.display());
        reject_command_secret_path_tokens(&cmd, &policy)
            .expect_err("argv must dest-deny symlink token to .env");
    }
    reject_command_secret_path_tokens("ls -la", &policy).expect("flags still pass");
    reject_command_secret_path_tokens("echo hello", &policy).expect("plain words still pass");
    reject_command_secret_path_tokens("cat .env.example", &policy).expect("template still allowed");
}

#[test]
fn argv_shell_meta_bash_c_interpreter_function_call_and_git_colon() {
    let policy = DenyPolicy::default();
    reject_command_secret_path_tokens("cat .env;", &policy).expect_err("trailing semicolon");
    reject_command_secret_path_tokens("cat .env)", &policy).expect_err("trailing paren");
    reject_command_secret_path_tokens("bash -c 'cat .env'", &policy).expect_err("quoted bash -c");
    reject_command_secret_path_tokens("python3 -c \"print(open('.env').read())\"", &policy)
        .expect_err("interpreter quoted path");
    let err = reject_command_secret_path_tokens("python3 -c open('.env')", &policy)
        .expect_err("function-call quoted path");
    assert!(
        err.to_string().contains("open('.env')"),
        "function-call close paren must keep quoted .env, got: {err}"
    );
    reject_command_secret_path_tokens("git show HEAD:.env", &policy)
        .expect_err("git colon pathspec");
    reject_command_secret_path_tokens("cat .env.example", &policy)
        .expect("template exception still allowed");
    reject_command_secret_path_tokens("git show HEAD:src/main.rs", &policy)
        .expect("non-secret pathspec ok");
}

#[test]
fn check_command_dests_joins_quoted_c_body_under_root_not_cwd() {
    let ws = tempfile::tempdir().expect("workspace");
    let _other = tempfile::tempdir().expect("other cwd");
    let env = ws.path().join(".env");
    std::fs::write(&env, "SECRET=1\n").expect("write .env");
    std::fs::hard_link(&env, ws.path().join("notes.txt")).expect("hardlink");
    let policy = DenyPolicy::default();
    let err = check_command_dests("sh -c 'cat notes.txt'", ws.path(), &policy)
        .expect_err("quoted -c notes.txt hardlink must dest-deny");
    match err {
        CheckDestError::DestDeny(DestDenyError::Denied(d)) => {
            assert_eq!(
                d.kind,
                DestDenyKind::HardlinkSibling,
                "joined notes.txt must be HardlinkSibling, got {:?}",
                d.kind
            );
        }
        other => panic!("expected DestDeny HardlinkSibling, got {other:?}"),
    }
}

#[test]
fn check_command_argv_denies_spaced_hardlink_token() {
    let ws = tempfile::tempdir().expect("workspace");
    let env = ws.path().join(".env");
    std::fs::write(&env, "SECRET=1\n").expect("write .env");
    std::fs::hard_link(&env, ws.path().join("my notes.txt")).expect("hardlink");
    let policy = DenyPolicy::default();
    let err = check_command_argv(&["/bin/cat", "my notes.txt"], ws.path(), &policy)
        .expect_err("raw argv my notes.txt hardlink must dest-deny");
    match err {
        CheckDestError::DestDeny(DestDenyError::Denied(d)) => {
            assert_eq!(
                d.kind,
                DestDenyKind::HardlinkSibling,
                "spaced argv dest must be HardlinkSibling, got {:?}",
                d.kind
            );
        }
        other => panic!("expected DestDeny HardlinkSibling, got {other:?}"),
    }
}

#[test]
fn check_command_argv_denies_c_body_hardlink_under_root() {
    let ws = tempfile::tempdir().expect("workspace");
    let env = ws.path().join(".env");
    std::fs::write(&env, "SECRET=1\n").expect("write .env");
    std::fs::hard_link(&env, ws.path().join("notes.txt")).expect("hardlink");
    let policy = DenyPolicy::default();
    let err = check_command_argv(&["/bin/sh", "-c", "cat notes.txt"], ws.path(), &policy)
        .expect_err("-c body notes.txt hardlink must dest-deny");
    match err {
        CheckDestError::DestDeny(DestDenyError::Denied(d)) => {
            assert_eq!(
                d.kind,
                DestDenyKind::HardlinkSibling,
                "-c body dest must be HardlinkSibling, got {:?}",
                d.kind
            );
        }
        other => panic!("expected DestDeny HardlinkSibling, got {other:?}"),
    }
}

#[test]
fn path_is_denied_table() {
    let deny = default_secret_denies();
    assert!(path_is_denied_glob(&deny, "/tmp/x/.env"));
    assert!(path_is_denied_glob(&deny, "keys/server.pem"));
    assert!(path_is_denied_glob(&deny, "app/secrets/token.txt"));
    assert!(path_is_denied_glob(&deny, "home/.ssh/id_ed25519"));
    assert!(path_is_denied_glob(&deny, "home/.ssh/id_dsa"));
    assert!(path_is_denied_glob(&deny, "home/.ssh/id_eddsa"));
    assert!(path_is_denied_glob(&deny, "ID_RSA"));
    assert!(path_is_denied_glob(&deny, "home/.pypirc"));
    assert!(path_is_denied_glob(&deny, "home/.docker/config.json"));
    assert!(path_is_denied_glob(&deny, "kubeconfig"));
    assert!(path_is_denied_glob(&deny, "app/secrets.json"));
    assert!(path_is_denied_glob(&deny, "app/service-account.json"));
    assert!(path_is_denied_glob(&deny, "app/service-account-foo.json"));
    assert!(path_is_denied_glob(&deny, "token.json"));
    assert!(path_is_denied_glob(&deny, "secring.gpg"));
    assert!(path_is_denied_glob(&deny, "credentials.json"));
    assert!(path_is_denied_glob(&deny, "home/.aws/credentials"));
    assert!(path_is_denied_glob(&deny, "home/.netrc"));
    assert!(path_is_denied_glob(&deny, "home/.ssh/config"));
    assert!(path_is_denied_glob(&deny, "home/.npmrc"));
    assert!(path_is_denied_glob(&deny, "home/.kube/config"));
    assert!(path_is_denied_glob(
        &deny,
        "home/.gnupg/private-keys-v1.d/foo"
    ));
    assert!(!path_is_denied_glob(&deny, "src/lib.rs"));
    assert!(!path_is_denied_glob(&deny, "src/secrets.rs"));
    assert!(path_is_denied_glob(&deny, ".env.local"));
    assert!(!path_is_denied_glob(&deny, ".env.example"));
    assert!(!path_is_denied_glob(&deny, "proj/.env.sample"));
    assert!(!path_is_denied_glob(&deny, "app/.env.template"));
    assert!(
        path_is_denied_glob(&deny, "proj/.ENV"),
        "live env deny must be case-insensitive"
    );
    assert!(!path_is_denied_glob(&deny, ".ENV.example"));
    assert!(path_is_denied_glob(&deny, "keys/SERVER.PEM"));
    assert!(path_is_denied_glob(&deny, "app/SECRETS/token.txt"));
    assert!(path_is_denied_glob(&deny, "app/gateway/pairing.json"));
    assert!(!path_is_denied_glob(&deny, "pairing.json"));
    assert!(path_is_denied_glob(&deny, "auth.json"));
    assert!(path_is_denied_glob(&deny, "home/bline/auth-work.json"));
}

#[test]
fn classify_dest_does_not_treat_dotdot_as_dest_deny() {
    let policy = DenyPolicy::default();
    assert_eq!(
        classify_dest(Path::new("../src/lib.rs"), &policy),
        None,
        "out-of-tree is PathGuard, not dest-deny"
    );
}

#[test]
fn deny_patch_dests_secret_denied_clean_allowed() {
    let policy = DenyPolicy::default();
    let err = deny_patch_dests(&[Path::new(".env")], &policy).expect_err("secret dest denied");
    match err {
        DestDenyError::Denied(denied) => assert_eq!(denied.kind, DestDenyKind::DenyGlob),
        other => panic!("expected Denied, got {other}"),
    }
    deny_patch_dests(&[Path::new("src/lib.rs")], &policy).expect("clean dest allowed");
}

#[test]
fn deny_patch_dests_with_display_uses_host_string() {
    let policy = DenyPolicy::default();
    let err = deny_patch_dests_with_display(&[(Path::new(".env"), "workspace:.env")], &policy)
        .expect_err("denied");
    let msg = err.to_string();
    assert!(msg.contains("workspace:.env"), "{msg}");
}

#[test]
fn deny_policy_clone_shares_globs() {
    let a = DenyPolicy::default();
    let b = a.clone();
    assert_eq!(a.globs() as *const [String], b.globs() as *const [String]);
    assert_eq!(a, b);
}

#[test]
fn deny_policy_from_arc_shares_allocation() {
    use std::sync::Arc;
    let globs = Arc::new(vec!["**/.env".into(), "**/.env.*".into()]);
    let policy = DenyPolicy::from_arc(Arc::clone(&globs));
    assert!(Arc::ptr_eq(&globs, &policy.globs_arc()));
    assert_eq!(policy.globs(), globs.as_slice());
}

#[test]
fn check_dest_raw_env_is_dest_deny_before_guard() {
    let policy = DenyPolicy::default();
    let dir = tempfile::tempdir().expect("tempdir");
    let guard =
        PathGuard::new(dir.path(), workpen::AbsolutePathPolicy::AllowIfContained).expect("guard");
    let err = check_dest(".env", &policy, Some(&guard)).expect_err("raw .env");
    match err {
        CheckDestError::DestDeny(DestDenyError::Denied(d)) => {
            assert_eq!(d.kind, DestDenyKind::DenyGlob);
        }
        other => panic!("expected dest-deny, got {other}"),
    }
}

#[test]
fn check_dest_none_does_not_jail_dotdot() {
    let policy = DenyPolicy::default();
    let got = check_dest("../src/lib.rs", &policy, None).expect(".. is PathGuard, not dest-deny");
    let want = std::env::current_dir().expect("cwd").join("../src/lib.rs");
    assert_eq!(got, want);
}

#[test]
fn check_dest_none_missing_is_cwd_joined() {
    let policy = DenyPolicy::default();
    let got = check_dest("no-such-workpen-dest-xyz", &policy, None).expect("missing dest");
    let want = std::env::current_dir()
        .expect("cwd")
        .join("no-such-workpen-dest-xyz");
    assert_eq!(got, want);
}

#[test]
fn check_dest_none_existing_is_canonical() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("readme.md");
    std::fs::write(&file, "ok\n").expect("write");
    let policy = DenyPolicy::default();
    let got = check_dest(&file.to_string_lossy(), &policy, None).expect("clean dest");
    let want = std::fs::canonicalize(&file).expect("canon");
    assert_eq!(got, want);
}

#[test]
fn check_dest_guard_escape_is_path_guard() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    let file = outside.path().join("notes.txt");
    std::fs::write(&file, "ok\n").expect("write");
    let guard =
        PathGuard::new(dir.path(), workpen::AbsolutePathPolicy::AllowIfContained).expect("guard");
    let policy = DenyPolicy::default();
    let err =
        check_dest(&file.to_string_lossy(), &policy, Some(&guard)).expect_err("outside workspace");
    match err {
        CheckDestError::PathGuard(_) => {}
        other => panic!("expected PathGuard, got {other}"),
    }
}

#[cfg(unix)]
#[test]
fn check_dest_resolved_symlink_to_env_is_dest_deny() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join(".env");
    std::fs::write(&env, "SECRET=1\n").expect("write .env");
    let alias = dir.path().join("config");
    std::os::unix::fs::symlink(&env, &alias).expect("symlink");
    let guard =
        PathGuard::new(dir.path(), workpen::AbsolutePathPolicy::AllowIfContained).expect("guard");
    let policy = DenyPolicy::default();
    let err =
        check_dest(&alias.to_string_lossy(), &policy, Some(&guard)).expect_err("symlink to .env");
    match err {
        CheckDestError::DestDeny(DestDenyError::Denied(d)) => {
            assert_eq!(d.kind, DestDenyKind::DenyGlob);
        }
        other => panic!("expected dest-deny, got {other}"),
    }
}

#[test]
fn verify_post_open_same_file_passes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("safe.txt");
    std::fs::write(&file, "content").expect("write");
    let fd = std::fs::File::open(&file).expect("open");
    let policy = DenyPolicy::default();
    verify_post_open(&file, &fd, &policy).expect("same inode");
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn verify_post_open_inode_mismatch_is_toctou() {
    let dir = tempfile::tempdir().expect("tempdir");
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    std::fs::write(&a, "a").expect("write a");
    std::fs::write(&b, "b").expect("write b");
    let fd = std::fs::File::open(&a).expect("open a");
    let policy = DenyPolicy::default();
    let err = verify_post_open(&b, &fd, &policy).expect_err("mismatch");
    let msg = err.to_string();
    assert!(msg.contains("TOCTOU"), "{msg}");
}

#[test]
fn verify_post_open_late_hardlink_wording_is_distinct() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join(".env");
    std::fs::write(&env, "API_KEY=secret\n").expect("write .env");
    let sibling = dir.path().join("notes.txt");
    std::fs::hard_link(&env, &sibling).expect("hardlink");
    let fd = std::fs::File::open(&sibling).expect("open sibling");
    let policy = DenyPolicy::default();
    let err = verify_post_open(&sibling, &fd, &policy).expect_err("late hardlink");
    let msg = err.to_string().to_ascii_lowercase();
    assert!(msg.contains("hardlink of a denied name"), "{msg}");
    assert!(msg.contains("unlink extra names"), "{msg}");
    assert!(!msg.contains("matches deny glob"), "{msg}");
    let pre = dest_deny_message(&sibling, &sibling.to_string_lossy(), &policy)
        .expect("pre-open sibling dest-deny")
        .to_ascii_lowercase();
    assert!(!pre.contains("unlink extra names"), "{pre}");
}

#[test]
fn existing_directory_is_not_a_hardlink_sibling() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("lib")).expect("src/lib");
    let policy = DenyPolicy::default();
    assert!(
        !is_path_denied(&src, &policy),
        "directory nlink must not dest-deny src/"
    );
    assert_eq!(classify_dest(&src, &policy), None);
}

#[test]
fn missing_path_is_not_a_hardlink_hit() {
    let policy = DenyPolicy::default();
    assert!(classify_dest(Path::new("no-such-workpen-hardlink-xyz"), &policy).is_none());
}

#[cfg(unix)]
#[test]
fn hardlink_stat_permission_denied_is_fail_closed() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join(".env");
    std::fs::write(&env, "API_KEY=secret\n").expect("write .env");
    let sibling = dir.path().join("notes.txt");
    std::fs::hard_link(&env, &sibling).expect("hardlink");
    let policy = DenyPolicy::default();

    struct RestoreMode<'a>(&'a Path);
    impl Drop for RestoreMode<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o700));
        }
    }
    let _restore = RestoreMode(dir.path());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o000))
        .expect("chmod 000");

    // Parent mode 000 makes sibling metadata PermissionDenied, not NotFound.
    match classify_dest(&sibling, &policy) {
        Some(DestDenyKind::HardlinkSibling) => {}
        other => panic!(
            "hardlink stat PermissionDenied must fail closed as HardlinkSibling, got {other:?}"
        ),
    }
}

#[test]
fn cross_dir_hardlink_of_env_is_denied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join(".env");
    std::fs::write(&env, "API_KEY=secret\n").expect("write .env");
    let src = dir.path().join("src");
    std::fs::create_dir(&src).expect("src");
    let alias = src.join("config.rs");
    std::fs::hard_link(&env, &alias).expect("cross-dir hardlink");
    let policy = DenyPolicy::default();
    match classify_dest(&alias, &policy) {
        Some(DestDenyKind::HardlinkSibling) => {}
        other => panic!("cross-dir hardlink of .env must be HardlinkSibling, got {other:?}"),
    }
    let innocent = dir.path().join("readme.md");
    std::fs::write(&innocent, "ok\n").expect("readme");
    let copy = dir.path().join("readme-copy.md");
    std::fs::hard_link(&innocent, &copy).expect("same-dir innocent hardlink");
    assert!(
        !is_path_denied(&copy, &policy),
        "same-dir hardlink of a non-secret file must still be allowed"
    );
}

#[cfg(unix)]
#[test]
fn verify_post_open_detects_symlink_swap_after_check() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("victim.txt");
    let outside = dir.path().join("outside-secret.txt");
    std::fs::write(&path, "safe").expect("victim");
    std::fs::write(&outside, "leaked").expect("outside");
    std::fs::remove_file(&path).expect("remove");
    std::os::unix::fs::symlink(&outside, &path).expect("swap");
    let fd = std::fs::File::open(&path).expect("open follows symlink");
    let policy = DenyPolicy::default();
    let err = verify_post_open(&path, &fd, &policy).expect_err("symlink swap");
    let msg = err.to_string();
    assert!(msg.contains("TOCTOU"), "{msg}");
    assert!(
        !msg.to_ascii_lowercase().contains("unlink extra names"),
        "{msg}"
    );
}

#[test]
fn glob_named_directory_is_still_deny_glob() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ssh = dir.path().join(".ssh");
    std::fs::create_dir_all(ssh.join("config.d")).expect(".ssh");
    let policy = DenyPolicy::default();
    match classify_dest(&ssh, &policy) {
        Some(DestDenyKind::DenyGlob) => {}
        other => panic!("basename glob must still dest-deny .ssh/, got {other:?}"),
    }
}

#[test]
fn check_dest_rejects_nul_byte() {
    let policy = DenyPolicy::default();
    match check_dest("foo\0bar", &policy, None) {
        Err(CheckDestError::Nul) => {}
        other => panic!("NUL must be CheckDestError::Nul, got {other:?}"),
    }
}

#[test]
fn extra_glob_id_rsa_matches_basename() {
    let policy = DenyPolicy::with_extra(["id_rsa".into()]);
    let path = Path::new("/tmp/id_rsa");
    assert!(
        is_path_denied(path, &policy),
        "extra glob id_rsa (no **/) must match /tmp/id_rsa basename"
    );
    match check_dest("/tmp/id_rsa", &policy, None) {
        Err(CheckDestError::DestDeny(DestDenyError::Denied(d))) => {
            assert_eq!(d.kind, DestDenyKind::DenyGlob);
        }
        other => panic!("expected dest-deny, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn check_dest_refuses_fifo() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = dir.path().join("pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    if !status.success() {
        return;
    }
    let policy = DenyPolicy::default();
    match check_dest(&fifo.to_string_lossy(), &policy, None) {
        Err(CheckDestError::SpecialFile { kind, .. }) => assert_eq!(kind, "fifo"),
        other => panic!("fifo must be SpecialFile, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn check_dest_refuses_device() {
    let path = Path::new("/dev/null");
    if !path.exists() {
        return;
    }
    let policy = DenyPolicy::default();
    match check_dest("/dev/null", &policy, None) {
        Err(CheckDestError::SpecialFile { kind, .. }) => assert_eq!(kind, "device"),
        other => panic!("device must be SpecialFile, got {other:?}"),
    }
}

#[test]
fn open_verified_read_allows_plain_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("notes.txt");
    std::fs::write(&file, "ok\n").expect("write");
    let policy = DenyPolicy::default();
    let got = open_verified_read(&file.to_string_lossy(), &policy, None).expect("open");
    drop(got);
}

#[test]
fn open_verified_read_refuses_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src");
    std::fs::create_dir(&src).expect("src");
    let policy = DenyPolicy::default();
    let path = src.to_string_lossy();
    check_dest(&path, &policy, None).expect("check_dest still allows directories");
    match open_verified_read(&path, &policy, None) {
        Err(CheckDestError::Directory { .. }) => {}
        other => panic!("directory must be CheckDestError::Directory, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn check_dest_refuses_unix_socket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("s.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
    let policy = DenyPolicy::default();
    match check_dest(&sock.to_string_lossy(), &policy, None) {
        Err(CheckDestError::SpecialFile { kind, .. }) => assert_eq!(kind, "socket"),
        other => panic!("socket must be SpecialFile, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn open_verified_read_symlink_to_env_is_dest_deny() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env = dir.path().join(".env");
    std::fs::write(&env, "SECRET=1\n").expect("write .env");
    let alias = dir.path().join("readme.txt");
    std::os::unix::fs::symlink(&env, &alias).expect("symlink");
    let policy = DenyPolicy::default();
    match open_verified_read(&alias.to_string_lossy(), &policy, None) {
        Err(CheckDestError::DestDeny(DestDenyError::Denied(d))) => {
            assert_eq!(d.kind, DestDenyKind::DenyGlob);
        }
        other => panic!("symlink to .env must dest-deny, got {other:?}"),
    }
}
