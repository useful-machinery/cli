use std::io;
use std::path::PathBuf;

/// The standalone driver takes the candidate executable `scripts/test-e2e` exports.
pub(super) fn resolve() -> io::Result<PathBuf> {
    let path = std::env::var_os("USEFUL_TEST_BINARY")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("supply a candidate with scripts/test-e2e"))?;
    std::fs::canonicalize(path)
}
