#[path = "support/candidate.rs"]
mod candidate;

fn cases(pattern: &str) -> std::io::Result<()> {
    let root = std::path::Path::new(file!())
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let pattern = root.join("cmd").join(pattern);
    trycmd::TestCases::new()
        .register_bin("useful", candidate::resolve()?)
        .case(pattern);
    Ok(())
}

#[test]
fn help_snapshots_match_rendered_output() -> std::io::Result<()> {
    cases("help/*.trycmd")
}

#[test]
fn workflow_input_failure_diagnostic_snapshot() -> std::io::Result<()> {
    cases("workflow-input-failure.trycmd")
}
