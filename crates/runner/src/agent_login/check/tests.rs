use std::fs;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

use super::*;

const RUNNERS_TOKEN: &str = "sk-ant-oat01-the-runners-claude-code-token";

/// A process snapshot that carries the host's own Claude Code key, its
/// configuration directory and token, a GitHub token, `HOME` and one other
/// name.
fn process() -> EnvironmentSnapshot {
    EnvironmentSnapshot::new(
        [
            ("ANTHROPIC_API_KEY", "service-anthropic-key"),
            ("CLAUDE_CONFIG_DIR", "/service/claude"),
            (
                CLAUDE_CODE_LOGIN_VARIABLE,
                "sk-ant-oat01-the-services-own-token",
            ),
            ("GH_TOKEN", "service-gh-token"),
            ("HOME", "/service/home"),
            ("SERVICE_OTHER", "kept"),
        ]
        .map(|(name, value)| (OsString::from(name), OsString::from(value))),
    )
}

/// The runner's agent-login directory in a fresh private state directory,
/// keeping `RUNNERS_TOKEN` as its Claude Code token, as setup leaves it.
fn keeping_the_runners_token() -> (tempfile::TempDir, LoginDirectory) {
    let state = tempfile::tempdir().unwrap();
    let directory = LoginDirectory::beside(&state.path().join("runner-state.json"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(directory.path())
        .unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.claude_code_token())
        .unwrap();
    std::io::Write::write_all(&mut file, RUNNERS_TOKEN.as_bytes()).unwrap();
    (state, directory)
}

fn value<'a>(environment: &'a EnvironmentSnapshot, name: &str) -> Option<&'a OsStr> {
    environment.variable(OsStr::new(name))
}

#[test]
fn a_check_made_under_cloud_runs_with_the_runners_login_and_without_the_blocked_names() {
    let (_state, directory) = keeping_the_runners_token();

    let environment = checked_environment(
        &process(),
        Some(CredentialMode::Cloud),
        &directory,
        CLAUDE_CODE_LOGIN_VARIABLE,
        claude_code::offered_token,
    );

    assert_eq!(
        value(&environment, CLAUDE_CODE_LOGIN_VARIABLE),
        Some(OsStr::new(RUNNERS_TOKEN))
    );
    for name in ["ANTHROPIC_API_KEY", "CLAUDE_CONFIG_DIR", "GH_TOKEN"] {
        assert_eq!(value(&environment, name), None, "{name}");
    }
    assert_eq!(
        value(&environment, "HOME"),
        Some(OsStr::new("/service/home"))
    );
    assert_eq!(
        value(&environment, "SERVICE_OTHER"),
        Some(OsStr::new("kept"))
    );
    assert_eq!(environment.variables().len(), 3);
}

#[test]
fn a_check_made_under_no_mode_runs_with_the_process_environment_but_the_logins_variable() {
    let (_state, directory) = keeping_the_runners_token();
    let process = process();

    let environment = checked_environment(
        &process,
        None,
        &directory,
        CLAUDE_CODE_LOGIN_VARIABLE,
        claude_code::offered_token,
    );

    // The service has a Claude Code login of its own, so the offer sets
    // none and the check never falls back to the service's.
    let mut expected = process.variables().clone();
    expected.remove(OsStr::new(CLAUDE_CODE_LOGIN_VARIABLE));
    assert_eq!(environment.variables(), &expected);
}
