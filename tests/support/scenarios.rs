#[derive(serde::Deserialize)]
pub(crate) struct Scenario {
    pub(crate) title: String,
    pub(crate) steps: Vec<Vec<String>>,
}

/// The design export's scenarios, each under its title with its steps in the export's order,
/// held as argument vectors. A step is the export's own words except where the export does
/// not write arguments a parser accepts:
///
/// - "Start runs from CI with a service principal" holds a well-formed `prn_` principal ID
///   for the export's `svc_01jcqa…`, since `--account` takes a principal ID, and a
///   well-formed invitation ID for its `inv_01jcqb`. Its last step is held without the
///   export's `USEFUL_ORG=dunder-mifflin USEFUL_PROJECT=paper` prefix, which is the
///   environment and not arguments.
/// - "Turn on automatic starts and see why one did not fire" holds a well-formed start
///   evaluation ID for the export's `wev_01jcqc`.
pub(crate) fn scenarios() -> serde_json::Result<Vec<Scenario>> {
    serde_json::from_str(include_str!("../fixtures/command-scenarios.json"))
}

/// A command that takes a flag its export form does not write, because what would make the
/// flag unnecessary waits on a Cloud change.
pub(crate) struct WaitsOnCloud {
    pub(crate) command: &'static str,
    pub(crate) flag: &'static str,
    pub(crate) value: &'static str,
    pub(crate) required: bool,
    pub(crate) cloud_change: &'static str,
}

pub(crate) const WAITS_ON_CLOUD: &[WaitsOnCloud] = &[
    // Without `--installation`, `connect github` prints the installation page.
    WaitsOnCloud {
        command: "org integration connect",
        flag: "installation",
        value: "12345678",
        required: false,
        cloud_change: "Cloud observing the GitHub App's installation callback",
    },
    WaitsOnCloud {
        command: "project webhook delivery show",
        flag: "webhook",
        value: "wh_01jcqd",
        required: true,
        cloud_change: "a lookup of a delivery by its ID",
    },
    WaitsOnCloud {
        command: "project webhook delivery replay",
        flag: "webhook",
        value: "wh_01jcqd",
        required: true,
        cloud_change: "a lookup of a delivery by its ID",
    },
    WaitsOnCloud {
        command: "runner credential revoke",
        flag: "runner",
        value: "scranton-1",
        required: true,
        cloud_change: "a lookup of a runner credential by its ID",
    },
    WaitsOnCloud {
        command: "workflow definition evaluation show",
        flag: "definition",
        value: "engineering",
        required: true,
        cloud_change: "a lookup of a start evaluation by its ID",
    },
    WaitsOnCloud {
        command: "workflow run publication show",
        flag: "run",
        value: "AUTO-12",
        required: true,
        cloud_change: "a lookup of a Publication by its ID",
    },
];
