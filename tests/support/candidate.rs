use std::io;
use std::path::PathBuf;

/// The executable under test. The workspace suite always runs the binary Cargo built for
/// it, so `USEFUL_TEST_BINARY` in a developer's or a harness script's environment cannot
/// retarget its implementation-only cases. The standalone driver has no such binary and
/// takes the candidate `scripts/test-e2e` exports.
pub(super) fn resolve() -> io::Result<PathBuf> {
    let path = option_env!("CARGO_BIN_EXE_useful")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USEFUL_TEST_BINARY").map(PathBuf::from))
        .ok_or_else(|| io::Error::other("supply a candidate with scripts/test-e2e"))?;
    std::fs::canonicalize(path)
}
