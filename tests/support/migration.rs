const GUIDE: &str = include_str!("../../docs/command-migration.md");

/// The option spellings the tree retired, each with the command paths that still hold an
/// option of that spelling for another meaning.
pub(crate) const RETIRED_OPTIONS: &[(&str, &[&str])] = &[
    ("cloud", &[]),
    ("cloud-to", &[]),
    ("cloud-new", &[]),
    ("no-owner", &[]),
    ("service-api-key-file", &[]),
    ("pool-id", &[]),
    ("project-id", &[]),
    ("runner-id", &[]),
    ("organization-id", &[]),
    ("organization", &[]),
    ("display-name", &["workflow run create"]),
    ("clear-display-name", &[]),
    ("stop-before", &[]),
    ("list-checks", &[]),
    ("connect", &[]),
    ("readiness", &[]),
    ("grants", &[]),
    ("require-grants", &[]),
    ("replace", &[]),
    ("activation-file", &[]),
    ("at", &[]),
    (
        "from",
        &[
            "workflow run handover",
            "workflow run retry",
            "workflow run upgrade",
        ],
    ),
    ("installation-id", &[]),
    ("gitlab-connection-id", &[]),
    ("repository-id", &["org integration repository list"]),
    ("provider-installation-id", &[]),
    ("input-set-id", &[]),
    ("principal-id", &[]),
    ("enable-state-updates", &[]),
    ("run-id", &[]),
    ("resume", &[]),
];

/// One row of a guide table: an earlier path and its replacements, `None` for `Retired`.
pub(crate) struct Row {
    pub(crate) earlier: String,
    pub(crate) replacements: Option<Vec<String>>,
}

/// The code spans of a table cell, when the cell is nothing but code spans separated by
/// commas.
fn code_spans(cell: &str) -> Option<Vec<&str>> {
    let mut spans = Vec::new();
    let mut rest = cell.trim();
    loop {
        let (span, after) = rest.strip_prefix('`')?.split_once('`')?;
        spans.push(span);
        rest = after.trim_start();
        if rest.is_empty() {
            return Some(spans);
        }
        rest = rest.strip_prefix(',')?.trim_start();
    }
}

/// The path a `useful …` code span names, without `useful`.
fn command_path(span: &str) -> Option<String> {
    span.strip_prefix("useful ").map(str::to_owned)
}

/// The rows of the table under the level-two heading `heading`.
pub(crate) fn guide_rows(heading: &str) -> Vec<Row> {
    let mut in_section = false;
    let mut rows = Vec::new();
    for line in GUIDE.lines() {
        if let Some(title) = line.strip_prefix("## ") {
            in_section = title.trim() == heading;
            continue;
        }
        let Some(inner) = line
            .trim()
            .strip_prefix('|')
            .and_then(|line| line.strip_suffix('|'))
        else {
            continue;
        };
        if !in_section {
            continue;
        }
        let cells: Vec<&str> = inner.split('|').collect();
        let Some(earlier) = code_spans(cells[0])
            .filter(|spans| spans.len() == 1)
            .and_then(|spans| command_path(spans[0]))
        else {
            continue;
        };
        assert_eq!(cells.len(), 2, "row of {earlier:?} has two cells");
        let replacements = if cells[1].trim() == "Retired" {
            None
        } else {
            let spans = code_spans(cells[1])
                .unwrap_or_else(|| panic!("replacement of {earlier:?} is code spans"));
            Some(
                spans
                    .into_iter()
                    .map(|span| {
                        command_path(span).unwrap_or_else(|| {
                            panic!("replacement {span:?} of {earlier:?} is a `useful` path")
                        })
                    })
                    .collect(),
            )
        };
        rows.push(Row {
            earlier,
            replacements,
        });
    }
    rows
}
