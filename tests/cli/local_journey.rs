use super::workflow_run::isolated_command;
use serde_json::Value;
use std::fs;

#[test]
fn validate_create_list_show_and_view_follow_the_same_local_run() {
    let directory = tempfile::tempdir().unwrap();
    let credentials = super::private_credential_directory();
    let work = directory.path().join("checkout");
    let tree = work.join(".useful/starter");
    fs::create_dir_all(&tree).unwrap();
    fs::write(
        tree.join("workflow.yaml"),
        r#"schemaVersion: 1
steps:
  witness:
    kind: cmd
    command:
      argv: [sh, -c, "echo ran >> invocations"]
"#,
    )
    .unwrap();
    let invoke = |args: &[&str]| {
        let args: Vec<_> = args.iter().map(|s| (*s).to_owned()).collect();
        let output = isolated_command(&args)
            .current_dir(&work)
            .env("USEFUL_HOME", directory.path().join("home"))
            .env("HOME", directory.path())
            .env(
                super::CREDENTIALS_FILE_VARIABLE,
                credentials.path().join("absent"),
            )
            .env_remove("USEFUL_ORG")
            .env_remove("USEFUL_PROJECT")
            .env_remove("USEFUL_TEST_INTERNAL_WORKER_EXECUTABLE")
            .arg("--json")
            .output()
            .unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
        // Creation emits a stream, while inspection can pretty-print one document.
        serde_json::Deserializer::from_slice(&output.stdout)
            .into_iter::<Value>()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .pop()
            .unwrap()
    };
    assert_eq!(
        invoke(&["workflow", "validate", ".useful/starter"])["outcome"],
        "valid"
    );
    let created = invoke(&["workflow", "run", "create", "--path", ".useful/starter"]);
    let list = invoke(&["workflow", "run", "list", "--all"]);
    assert_eq!(list["cloud"]["asked"], false);
    let runs = list["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    let id = runs[0]["id"].as_str().unwrap();
    assert_eq!(runs[0]["directory"], created["runDirectory"]);
    let shown = invoke(&["workflow", "run", "show", id]);
    assert_eq!(shown["record"]["id"], id);
    assert_eq!(shown["record"]["state"], "exited");
    let viewed = invoke(&["workflow", "run", "view", id]);
    assert_eq!(viewed["attemptState"], "succeeded");
    assert_eq!(viewed["result"]["steps"][0]["id"], "witness");
    assert_eq!(fs::read(work.join("invocations")).unwrap(), b"ran\n");
}
