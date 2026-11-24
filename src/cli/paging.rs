//! The paging loop the commands that read a whole list share: each such list is read through
//! `every_page`. The subject lookup of `useful workflow run` reads within a bound of its own.

use std::collections::BTreeSet;

/// Reads a list to its last page, following each page's next cursor; `read` lists the page at
/// a cursor as its items and the next cursor. A next cursor already followed would page
/// forever, and is refused as `invalid`. The grant commands, the context resolution, `useful org
/// member` and `useful workflow doctor` all page through this one loop.
pub(super) fn every_page<T, E>(
    invalid: E,
    mut read: impl FnMut(Option<&str>) -> Result<(Vec<T>, Option<String>), E>,
) -> Result<Vec<T>, E> {
    let mut items = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor: Option<String> = None;
    loop {
        let (page, next) = read(cursor.as_deref())?;
        items.extend(page);
        let Some(next) = next else {
            return Ok(items);
        };
        if !seen.insert(next.clone()) {
            return Err(invalid);
        }
        cursor = Some(next);
    }
}

#[cfg(test)]
mod tests {
    use super::every_page;

    #[derive(Debug, PartialEq)]
    enum Failure {
        RepeatedCursor,
        Looped,
    }

    // The command reads every page, and a server whose cursors come back round to one
    // already followed ends the read with a failure rather than paging forever.
    #[test]
    fn a_cursor_seen_before_ends_the_read_with_a_failure() {
        let mut reads = Vec::new();
        let result = every_page(Failure::RepeatedCursor, |cursor| {
            reads.push(cursor.map(str::to_owned));
            let next = match cursor {
                None | Some("B") => "A",
                Some(_) => "B",
            };
            if reads.len() > 4 {
                return Err(Failure::Looped);
            }
            Ok((vec![reads.len()], Some(next.to_owned())))
        });

        assert_eq!(result, Err(Failure::RepeatedCursor));
        assert_eq!(
            reads,
            [None, Some("A".to_owned()), Some("B".to_owned())],
            "the read stops at the page that names A again"
        );
    }
}
