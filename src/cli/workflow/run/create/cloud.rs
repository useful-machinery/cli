//! `useful workflow run create DEFINITION --on personal|project` (REQ-RUN-94): a Cloud run of the
//! Cloud definition `DEFINITION` in the organization and project in effect (REQ-ORG-87,
//! REQ-PROJECT-100), created and reported as every Cloud run creation is: one idempotency key
//! for the invocation and the single resend (REQ-RUN-55 to REQ-RUN-57), the named inputs staged
//! and sealed first (REQ-RUNINPUT-53, REQ-RUNINPUT-54), `--wait` (REQ-RUN-58, REQ-RUN-61) and
//! the `create` document. What a Cloud `cancel`, `resume` and `retry` share with it lives in
//! `src/cli/workflow/run/cloud_api.rs`.

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context as _, anyhow};
use clap::Args;
use clap::builder::NonEmptyStringValueParser;
use useful_api::{CreateRunInput, RunDefinitionSelection, RunFailure};
use useful_execution::visible_text;
use useful_human_auth::Deployment;

use super::super::cloud_api::{
    CloudSnapshot, RunOptions, RunWaitArgs, acquisition, failure_code, finish_accepted,
    finish_cloud_observation, finish_operation, observation, start_cloud_observation, with_api,
    write_cloud, write_failure_with_input_set,
};
use super::super::target::Place;
use crate::cli::context::{OrgArgs, ProjectArgs};
use crate::cli::workflow::definition::target::{self, InEffect};
use crate::cli::workflow::input_set::{StagingRecovery, parse_input_set_id};
use crate::cli::{
    CommandFailure, CommandResult, CommonArgs, HttpOptions, PrincipalAuthenticationArgs,
};
use crate::exit_code::ExitCode;

/// The most simultaneous steps a Cloud run admits (REQ-RUN-84).
const MAXIMUM_CLOUD_PARALLEL_STEPS: usize = 64;

/// The options only a Cloud creation reads; each needs `--on personal` or `--on project`
/// (REQ-LOCALRUN-80).
#[derive(Debug, Args)]
pub(super) struct Options {
    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    project: ProjectArgs,

    #[command(flatten)]
    selection: CreationOptions,

    #[arg(long, value_name = "PATH|-", help = INTEGRATION_CONTEXT_FILE_HELP)]
    integration_context_file: Option<PathBuf>,

    #[command(flatten)]
    wait: RunWaitArgs,

    #[command(flatten)]
    authentication: PrincipalAuthenticationArgs,

    #[command(flatten)]
    http: HttpOptions,
}

impl Options {
    /// The first Cloud-only option given, by its flag, which `--on local` refuses
    /// (REQ-LOCALRUN-80).
    pub(super) fn given(&self) -> Option<&'static str> {
        [
            (self.org.given(), "--org"),
            (self.project.given(), "--project"),
        ]
        .into_iter()
        .find_map(|(given, flag)| given.then_some(flag))
        .or_else(|| self.selection.given())
        .or_else(|| {
            [
                (
                    self.integration_context_file.is_some(),
                    "--integration-context-file",
                ),
                (self.wait.wait, "--wait"),
                (self.wait.timeout.is_some(), "--timeout"),
                (self.authentication.api_key_file.is_some(), "--api-key-file"),
                (self.http.allow_insecure_http, "--allow-insecure-http"),
            ]
            .into_iter()
            .find_map(|(given, flag)| given.then_some(flag))
        })
    }
}

impl super::Command {
    /// Asks Cloud, in the organization and project in effect, to create a run of the Cloud
    /// definition `DEFINITION` and the workflow file `--workflow` names in its tree: an ID is
    /// sent as given and a name is the project's one definition of that name (REQ-CLOUDDEF-42).
    /// `--on project` asks for a run with no owner (REQ-RUN-99). Nothing under the `useful` home
    /// and no execution root is read.
    pub(super) fn create_in_cloud(self, place: Place) -> CommandResult {
        let usage = |error| CommandFailure::with_exit_code(error, ExitCode::UsageError);
        let named = self
            .definition
            .ok_or_else(|| usage(anyhow!("name the Cloud definition DEFINITION")))?;
        let workflow_path = match self.workflow.as_deref() {
            None => None,
            Some(workflow) => {
                super::tree_workflow_file(Some(workflow)).map_err(usage)?;
                if workflow.to_str().is_none() {
                    return Err(usage(anyhow!("--workflow must be valid UTF-8")));
                }
                Some(super::tree_relative_workflow(Some(workflow)))
            }
        };
        let max_parallel = self
            .max_parallel
            .map(|count| {
                u8::try_from(count)
                    .ok()
                    .filter(|_| count <= MAXIMUM_CLOUD_PARALLEL_STEPS)
                    .ok_or_else(|| {
                        usage(anyhow!(
                            "invalid value '{count}' for '--max-parallel <COUNT>': with --on {}, value must be between 1 and {MAXIMUM_CLOUD_PARALLEL_STEPS}",
                            place.as_str()
                        ))
                    })
            })
            .transpose()?;
        let json = self.presentation.output.json;
        let Options {
            org,
            project,
            selection,
            integration_context_file,
            wait,
            authentication,
            http,
        } = self.cloud_creation;
        let inputs = self.inputs;
        target::acting_in_project(
            named,
            InEffect::new(org, project),
            CommonArgs::new(json, authentication, http),
            super::definition_leaf(json),
            |deployment, options, project, id| {
                Creation {
                    organization: project.organization.clone(),
                    project_id: project.project.clone(),
                    definition: RunDefinitionSelection {
                        definition_id: id.to_owned(),
                        workflow_path,
                    },
                    selection,
                    inputs,
                    integration_context_file,
                    max_parallel,
                    unowned: place == Place::Project,
                    wait,
                    options: RunOptions::new(options.json, options.authentication, options.http),
                }
                .submit(deployment.clone())
            },
        )
    }
}

/// The help of `--integration-context-file` on the commands that create a Cloud run.
const INTEGRATION_CONTEXT_FILE_HELP: &str =
    "Read private immutable integration context from a JSON file, or - for standard input";

/// The source, workspace, name and input-set options of a Cloud run's creation (REQ-RUN-94).
#[derive(Debug, Args)]
struct CreationOptions {
    #[arg(
        long,
        value_name = "BRANCH",
        value_parser = NonEmptyStringValueParser::new(),
        help = "Source branch (the project default when omitted)"
    )]
    source_branch: Option<String>,

    #[arg(long, value_name = "BRANCH", conflicts_with = "workspace_commit",
        value_parser = NonEmptyStringValueParser::new(),
        help = "Workspace branch (the workflow source when omitted)")]
    workspace_branch: Option<String>,

    #[arg(
        long,
        value_name = "HASH",
        conflicts_with = "workspace_branch",
        help = "Workspace commit hash (the workflow source when omitted)"
    )]
    workspace_commit: Option<String>,

    #[arg(
        long,
        value_name = "NAME",
        value_parser = NonEmptyStringValueParser::new(),
        help = "Set the run display name"
    )]
    display_name: Option<String>,

    #[arg(
        long,
        value_name = "INPUT_SET",
        value_parser = parse_input_set_id,
        conflicts_with_all = [
            "input_text",
            "input_text_file",
            "input_json",
            "input_json_file",
            "input_file",
            "input_attachment",
            "input_attachments_empty"
        ],
        help = "Consume an existing sealed Run Input Set without restaging"
    )]
    input_set: Option<String>,
}

impl CreationOptions {
    /// The first of these options given, by its flag.
    fn given(&self) -> Option<&'static str> {
        [
            (self.source_branch.is_some(), "--source-branch"),
            (self.workspace_branch.is_some(), "--workspace-branch"),
            (self.workspace_commit.is_some(), "--workspace-commit"),
            (self.display_name.is_some(), "--display-name"),
            (self.input_set.is_some(), "--input-set"),
        ]
        .into_iter()
        .find_map(|(given, flag)| given.then_some(flag))
    }
}

/// One Cloud run creation and what follows its acceptance: one idempotency key for the
/// invocation, the single resend, the input staging, `--wait` and the `create` document
/// (REQ-RUN-55 to REQ-RUN-58, REQ-RUN-61, REQ-RUN-80).
struct Creation {
    /// The organization reference sent, as the organization in effect resolved it.
    organization: String,
    /// The project in effect's ID.
    project_id: String,
    /// The Cloud definition id as given, and a workflow file of its tree or none for the root
    /// (REQ-RUN-94).
    definition: RunDefinitionSelection,
    selection: CreationOptions,
    inputs: crate::cli::NamedInputArgs,
    integration_context_file: Option<PathBuf>,
    max_parallel: Option<u8>,
    /// `--on project`: the run starts with no owner (REQ-RUN-94, REQ-RUN-99).
    unowned: bool,
    wait: RunWaitArgs,
    options: RunOptions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CreateInputSetOwnership {
    Explicit(String),
    Allocated(String),
}

impl CreateInputSetOwnership {
    fn id(&self) -> &str {
        match self {
            Self::Explicit(input_set_id) | Self::Allocated(input_set_id) => input_set_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum CreateRecoveryState {
    BeforeRunDispatch(Option<CreateInputSetOwnership>),
    InputSetAllocationDispatched,
    RunDispatched(Option<CreateInputSetOwnership>, Option<String>),
    Accepted(CloudSnapshot),
}

impl StagingRecovery for CreateRecoveryState {
    fn input_set_allocation_dispatched() -> Self {
        Self::InputSetAllocationDispatched
    }

    fn allocated_input_set(input_set_id: &str) -> Self {
        Self::BeforeRunDispatch(Some(CreateInputSetOwnership::Allocated(
            input_set_id.to_owned(),
        )))
    }
}

impl CreateRecoveryState {
    fn new(explicit_input_set_id: Option<&str>) -> Self {
        Self::BeforeRunDispatch(
            explicit_input_set_id
                .map(|input_set_id| CreateInputSetOwnership::Explicit(input_set_id.to_owned())),
        )
    }

    fn run_dispatched(&self) -> Self {
        match self {
            Self::BeforeRunDispatch(input_set) | Self::RunDispatched(input_set, _) => {
                Self::RunDispatched(input_set.clone(), None)
            }
            Self::InputSetAllocationDispatched => Self::RunDispatched(None, None),
            Self::Accepted(snapshot) => Self::Accepted(snapshot.clone()),
        }
    }

    fn with_run_key(self, key: &str) -> Self {
        match self {
            Self::RunDispatched(input_set, _) => {
                Self::RunDispatched(input_set, Some(key.to_owned()))
            }
            other => other,
        }
    }

    fn input_set_id(&self) -> Option<&str> {
        match self {
            Self::BeforeRunDispatch(Some(input_set)) | Self::RunDispatched(Some(input_set), _) => {
                Some(input_set.id())
            }
            Self::BeforeRunDispatch(None)
            | Self::InputSetAllocationDispatched
            | Self::RunDispatched(None, _)
            | Self::Accepted(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum CreateSignalRecovery {
    None,
    InputSetUnknown,
    InputSet(String),
    Run(Option<String>, Option<String>),
    Accepted(CloudSnapshot),
}

fn create_signal_recovery(
    snapshot: crate::cli::SignalSnapshot<CreateRecoveryState>,
) -> CreateSignalRecovery {
    if !snapshot.dispatched {
        return CreateSignalRecovery::None;
    }
    match snapshot.recovery {
        CreateRecoveryState::InputSetAllocationDispatched => CreateSignalRecovery::InputSetUnknown,
        CreateRecoveryState::BeforeRunDispatch(Some(CreateInputSetOwnership::Allocated(
            input_set_id,
        ))) => CreateSignalRecovery::InputSet(input_set_id),
        CreateRecoveryState::BeforeRunDispatch(_) => CreateSignalRecovery::None,
        CreateRecoveryState::RunDispatched(input_set, key) => {
            CreateSignalRecovery::Run(input_set.map(|input_set| input_set.id().to_owned()), key)
        }
        CreateRecoveryState::Accepted(snapshot) => CreateSignalRecovery::Accepted(snapshot),
    }
}

impl Creation {
    fn submit(self, deployment: Deployment) -> crate::cli::CommandResult {
        let recovery = CreateRecoveryState::new(self.selection.input_set.as_deref());
        let signal_deployment = deployment.clone();
        let signal_organization = self.organization.clone();
        let signal_json = self.options.json;
        let timeout = self.wait.timeout.filter(|_| self.wait.wait);
        let timeout_deployment = signal_deployment.clone();
        let timeout_organization = signal_organization.clone();
        crate::cli::execute_mutation_with_signals_and_deferred_timeout(
            "Cloud run creation",
            recovery,
            timeout,
            move |control, timeout_start| {
                self.execute_blocking(&deployment, control, timeout_start)
            },
            move |signal, snapshot| match create_signal_recovery(snapshot) {
                CreateSignalRecovery::Run(input_set_id, key) => write_create_unknown(
                    signal_deployment.fingerprint().api_url(),
                    &signal_organization,
                    input_set_id.as_deref(),
                    key.as_deref(),
                    signal_json,
                    signal,
                )
                .map_err(Into::into),
                recovery @ (CreateSignalRecovery::InputSet(_)
                | CreateSignalRecovery::InputSetUnknown
                | CreateSignalRecovery::None) => {
                    if let CreateSignalRecovery::InputSet(input_set_id) = recovery {
                        write_staging_recovery(&signal_organization, &input_set_id)?;
                        if !signal_json {
                            return Ok(signal);
                        }
                    }
                    write_cloud!(
                        "create",
                        signal_deployment.fingerprint().api_url(),
                        &signal_organization,
                        &CloudSnapshot::default(),
                        "acceptance_unknown",
                        Some("acceptance_unknown"),
                        None,
                        None,
                        signal_json,
                        signal,
                    )
                    .map_err(Into::into)
                }
                CreateSignalRecovery::Accepted(snapshot) => write_cloud!(
                    "create",
                    signal_deployment.fingerprint().api_url(),
                    &signal_organization,
                    &snapshot,
                    "observation_stopped",
                    Some("observation_stopped"),
                    None,
                    None,
                    signal_json,
                    signal,
                )
                .map_err(Into::into),
            },
            move |snapshot| match snapshot.recovery {
                CreateRecoveryState::Accepted(snapshot) => write_cloud!(
                    "create",
                    timeout_deployment.fingerprint().api_url(),
                    &timeout_organization,
                    &snapshot,
                    "timed_out",
                    Some("wait_timed_out"),
                    None,
                    None,
                    signal_json,
                    ExitCode::GeneralFailure,
                )
                .map_err(Into::into),
                _ => Ok(ExitCode::GeneralFailure),
            },
        )
    }

    fn execute_blocking(
        self,
        deployment: &Deployment,
        control: &crate::cli::OperationControl<CreateRecoveryState>,
        timeout_start: &crate::cli::DeferredObservationTimeoutStart,
    ) -> crate::cli::CommandResult {
        if let Err(error) = acquisition::validate_standard_input_claims(
            &self.inputs,
            self.integration_context_file.as_deref(),
            self.options.authentication.uses_stdin(),
        ) {
            return finish_operation(control, || {
                write_input_acquisition_failure(
                    deployment.fingerprint().api_url(),
                    &self.organization,
                    &error,
                    self.options.json,
                )
            });
        }
        let integration_context = match acquisition::acquire_integration_context(
            self.integration_context_file.as_deref(),
        ) {
            Ok(context) => context,
            Err(error) => {
                return finish_operation(control, || {
                    write_input_acquisition_failure(
                        deployment.fingerprint().api_url(),
                        &self.organization,
                        &error,
                        self.options.json,
                    )
                });
            }
        };
        let acquired = if self.inputs.is_empty() {
            None
        } else {
            match acquisition::acquire(&self.inputs) {
                Ok(acquired) => Some(acquired),
                Err(error) => {
                    return finish_operation(control, || {
                        write_input_acquisition_failure(
                            deployment.fingerprint().api_url(),
                            &self.organization,
                            &error,
                            self.options.json,
                        )
                    });
                }
            }
        };
        let run_idempotency_key = useful_support::generate_idempotency_key()
            .context("generate Cloud run request identity")?;
        if control.is_cancelled() {
            return Ok(ExitCode::GeneralFailure);
        }

        let input_set_id = if let Some(acquired) = acquired.as_ref() {
            let staged = match crate::cli::workflow::input_set::stage_and_seal(
                deployment,
                self.options.http.transport_policy(),
                &self.options.authentication,
                &self.organization,
                &self.project_id,
                acquired,
                control,
            ) {
                Ok(staged) => staged,
                Err(error) => {
                    let recovery = control.recovery();
                    return finish_operation(control, || {
                        writeln!(
                            io::stderr().lock(),
                            "error: stage Run Input Set: {}\n\nResolve this error before creating another run.",
                            visible_text(&format!("{error:#}"))
                        )?;
                        if let Some(input_set_id) = recovery.input_set_id() {
                            write_staging_guidance(&self.organization, input_set_id)?;
                        }
                        write_cloud!(
                            "create",
                            deployment.fingerprint().api_url(),
                            &self.organization,
                            &CloudSnapshot::default(),
                            "error",
                            Some("submission_failed"),
                            None,
                            None,
                            self.options.json,
                            ExitCode::GeneralFailure,
                        )
                    });
                }
            };
            match staged {
                Ok(sealed) => sealed.id,
                Err(failure) => {
                    let recovery = control.recovery();
                    return finish_operation(control, || {
                        write_create(
                            deployment.fingerprint().api_url(),
                            &self.organization,
                            recovery.input_set_id(),
                            (None, false),
                            Err(failure),
                            self.options.authentication.kind(),
                            self.options.json,
                        )
                    });
                }
            }
        } else {
            self.selection.input_set.clone().unwrap_or_default()
        };
        let input_set_id = (!input_set_id.is_empty()).then_some(input_set_id);
        if control.is_cancelled() {
            return Ok(ExitCode::GeneralFailure);
        }

        let dispatch_recovery = control
            .recovery()
            .run_dispatched()
            .with_run_key(&run_idempotency_key);
        // Run dispatch owns cancellation recovery and a run-specific request envelope; it stays
        // explicit rather than sharing project creation's superficially similar API call.
        let result = with_api(
            deployment,
            self.options.http.transport_policy(),
            &self.options.authentication,
            |api| {
                api.create(
                    &self.organization,
                    &run_idempotency_key,
                    CreateRunInput {
                        project_id: &self.project_id,
                        definition: self.definition.clone(),
                        source_branch: self.selection.source_branch.as_deref(),
                        workspace_branch: self.selection.workspace_branch.as_deref(),
                        workspace_commit: self.selection.workspace_commit.as_deref(),
                        display_name: self.selection.display_name.as_deref(),
                        input_set_id: input_set_id.as_deref(),
                        integration_context: integration_context.as_ref(),
                        maximum_parallel_steps: self.max_parallel,
                        unowned: self.unowned,
                    },
                    || control.begin_dispatch_with_recovery(dispatch_recovery.clone()),
                )
            },
        );
        let result = match result {
            Ok(result) => result,
            Err(_) => {
                let recovery = control.recovery();
                let dispatched = matches!(recovery, CreateRecoveryState::RunDispatched(_, _));
                return finish_operation(control, || {
                    if let Some(input_set_id) = recovery.input_set_id() {
                        write_staging_guidance(&self.organization, input_set_id)?;
                    }
                    write_cloud!(
                        "create",
                        deployment.fingerprint().api_url(),
                        &self.organization,
                        &CloudSnapshot::default(),
                        if dispatched {
                            "acceptance_unknown"
                        } else {
                            "error"
                        },
                        Some(if dispatched {
                            "acceptance_unknown"
                        } else {
                            "submission_failed"
                        }),
                        dispatched.then_some(run_idempotency_key.as_str()),
                        None,
                        self.options.json,
                        if dispatched {
                            ExitCode::Unavailable
                        } else {
                            ExitCode::GeneralFailure
                        },
                    )
                });
            }
        };
        let acceptance = match result {
            Ok(acceptance) => acceptance,
            Err(failure) => {
                return finish_operation(control, || {
                    write_create(
                        deployment.fingerprint().api_url(),
                        &self.organization,
                        input_set_id.as_deref(),
                        (
                            Some(&run_idempotency_key),
                            matches!(control.recovery(), CreateRecoveryState::RunDispatched(_, _)),
                        ),
                        Err(failure),
                        self.options.authentication.kind(),
                        self.options.json,
                    )
                });
            }
        };
        let mut snapshot = CloudSnapshot::for_run(acceptance.run_id);
        snapshot.replayed = Some(acceptance.replayed);
        if !control.update_recovery(CreateRecoveryState::Accepted(snapshot.clone())) {
            return Ok(ExitCode::GeneralFailure);
        }
        if !self.wait.wait {
            return finish_accepted(
                control,
                "create",
                deployment,
                &self.organization,
                &snapshot,
                self.options.json,
            );
        }
        let (clock, started) = start_cloud_observation(timeout_start);
        let result = observation::wait_run(
            observation::ObservationContext {
                deployment,
                options: &self.options,
                organization: &self.organization,
                snapshot: &snapshot,
                timeout: self.wait.timeout,
                started,
            },
            control,
            &clock,
            |latest| {
                control.update_recovery(CreateRecoveryState::Accepted(latest));
            },
        );
        finish_cloud_observation(
            deployment.fingerprint().api_url(),
            "create",
            &self.organization,
            result,
            control,
            || {
                (
                    match control.recovery() {
                        CreateRecoveryState::Accepted(latest) => latest,
                        _ => snapshot.clone(),
                    },
                    None,
                    None,
                )
            },
            self.options.json,
        )
    }
}

pub(in crate::cli::workflow) fn write_input_acquisition_failure(
    deployment: &str,
    organization: &str,
    failure: &acquisition::InputAcquisitionFailure,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        return write_cloud!(
            "create",
            deployment,
            organization,
            &CloudSnapshot::default(),
            "error",
            Some("invalid_input"),
            None,
            None,
            true,
            ExitCode::GeneralFailure,
        );
    } else {
        writeln!(
            io::stderr().lock(),
            "error: acquire Cloud run request data: {}\n\nCorrect the named input sources, integration context, and limits, then try again.",
            visible_text(&failure.to_string())
        )?;
    }
    Ok(ExitCode::GeneralFailure)
}

fn write_create(
    deployment: &str,
    organization: &str,
    input_set_id: Option<&str>,
    submission: (Option<&str>, bool),
    result: Result<useful_api::RunCreationAcceptance, RunFailure>,
    authentication: crate::cli::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let (key, run_dispatched) = submission;
    if let Err(RunFailure::InputAdmissionRejected {
        status,
        problem_type,
        diagnostic,
    }) = &result
    {
        if json {
            super::super::cloud_api::output::write_admission_failure(
                deployment,
                organization,
                input_set_id,
                key,
                super::super::cloud_api::output::AdmissionProblem {
                    code: "input_admission_rejected",
                    status: *status,
                    problem_type,
                    diagnostic: diagnostic
                        .as_ref()
                        .map(|(code, input)| (*code, input.as_str())),
                    correlation_id: None,
                    blockers: &[],
                },
            )?;
        } else {
            let mut stderr = io::stderr().lock();
            writeln!(
                stderr,
                "error: Cloud run input admission rejected (HTTP {status})\nproblem type: https://api.usefulmachinery.com/problems/{problem_type}"
            )?;
            if let Some((code, input)) = diagnostic {
                writeln!(stderr, "diagnostic.code: {code}\ndiagnostic.input: {input}")?;
            }
            let remedy = match *problem_type {
                "run-input-set-not-sealed" => {
                    "Seal the retained input set before submitting again."
                }
                "run-input-set-consumed" | "run-input-set-expired" | "run-input-content-gone" => {
                    "Create and seal a new input set before submitting again."
                }
                _ => "Correct the named input's kind or schema and submit a corrected request.",
            };
            writeln!(
                stderr,
                "input set: {}\n\nInspect the input set with `useful workflow input-set show`. {remedy} This rejection did not create a run.",
                input_set_id.unwrap_or("none")
            )?;
        }
        return Ok(ExitCode::GeneralFailure);
    }
    // REQ-RUN-80: a definite admission rejection is rendered before the
    // dispatched-failure arm below, so it can never be reported as acceptance_unknown.
    if let Err(RunFailure::AdmissionRejected {
        status,
        problem_type,
        request_id,
        blockers,
    }) = &result
    {
        if json {
            super::super::cloud_api::output::write_admission_failure(
                deployment,
                organization,
                input_set_id,
                key,
                super::super::cloud_api::output::AdmissionProblem {
                    code: "admission_rejected",
                    status: *status,
                    problem_type,
                    diagnostic: None,
                    correlation_id: request_id.as_deref(),
                    blockers,
                },
            )?;
        } else {
            let remedy = match *problem_type {
                "project-archived" => crate::cli::project::ARCHIVED_REMEDY,
                "project-not-ready" => {
                    "The project is not ready to run workflows; inspect it with `useful project show` and clear the listed blockers before submitting a new request."
                }
                "workspace-selection-unsupported" => {
                    "This deployment does not admit an explicit workspace selection. Omit --workspace-branch and --workspace-commit and keep --source-branch; the workspace is then pinned at the workflow definition commit, which the acceptance receipt reports."
                }
                "workflow-source-unavailable" => {
                    "Check that the source branch exists, the workflow path exists on it and the repository can be read."
                }
                "workflow-source-invalid" => {
                    "Correct the workflow definition at the selected source."
                }
                _ => {
                    "Check that the selected workspace branch or commit exists on a connected branch of the repository."
                }
            };
            let mut stderr = io::stderr().lock();
            writeln!(
                stderr,
                "error: Cloud run admission rejected (HTTP {status})\nproblem type: https://api.usefulmachinery.com/problems/{problem_type}\nrequest id: {}",
                request_id.as_deref().unwrap_or("none")
            )?;
            if !blockers.is_empty() {
                writeln!(
                    stderr,
                    "blockers: {}",
                    crate::cli::project::blocker_list(blockers)
                )?;
            }
            writeln!(stderr, "\n{remedy} This rejection did not create a run.")?;
        }
        if let Some(input_set_id) = input_set_id {
            write_staging_guidance(organization, input_set_id)?;
        }
        return Ok(ExitCode::GeneralFailure);
    }
    match result {
        Ok(acceptance) => {
            if json {
                let mut snapshot = CloudSnapshot::for_run(&acceptance.run_id);
                snapshot.replayed = Some(acceptance.replayed);
                return write_cloud!(
                    "create",
                    deployment,
                    organization,
                    &snapshot,
                    "accepted",
                    None,
                    None,
                    None,
                    true,
                    ExitCode::Success,
                );
            } else {
                let stdout = io::stdout();
                let mut stdout = stdout.lock();
                writeln!(stdout, "✓ Run accepted.\n")?;
                writeln!(stdout, "run: {}", acceptance.run_id)?;
                writeln!(
                    stdout,
                    "replayed: {}",
                    if acceptance.replayed { "yes" } else { "no" }
                )?;
                if let Some(input_set_id) = input_set_id {
                    writeln!(stdout, "input set: {input_set_id}")?;
                }
                writeln!(stdout, "organization: {organization}")?;
                writeln!(stdout, "deployment: {deployment}")?;
            }
            Ok(ExitCode::Success)
        }
        Err(failure)
            if json
                || (run_dispatched
                    && matches!(failure,
                        RunFailure::Unreachable(category) if category != useful_api::UnreachableCategory::RateLimited
                    ))
                || (run_dispatched && matches!(failure, RunFailure::Protocol { .. })) =>
        {
            let (code, exit) = failure_code(&failure, authentication);
            let uncertain = run_dispatched
                && (matches!(failure,
                RunFailure::Unreachable(category) if category != useful_api::UnreachableCategory::RateLimited)
                    || matches!(failure, RunFailure::Protocol { .. }));
            if let Some(input_set_id) = input_set_id {
                write_staging_guidance(organization, input_set_id)?;
            }
            write_cloud!(
                "create",
                deployment,
                organization,
                &CloudSnapshot::default(),
                if uncertain {
                    "acceptance_unknown"
                } else {
                    "error"
                },
                Some(if uncertain {
                    "acceptance_unknown"
                } else {
                    code
                }),
                key,
                None,
                json,
                if uncertain {
                    ExitCode::Unavailable
                } else {
                    exit
                },
            )
        }
        Err(failure) => write_failure_with_input_set(
            deployment,
            organization,
            None,
            input_set_id,
            &failure,
            authentication,
            false,
        ),
    }
}

fn write_staging_guidance(organization: &str, input_set_id: &str) -> anyhow::Result<()> {
    writeln!(
        io::stderr().lock(),
        "input set: {input_set_id}\norganization: {organization}\n\nInspect with `useful workflow input-set show`; if open, resume upload and sealing, or delete the set explicitly. Reconcile any uncertain run acceptance before creating another run."
    )?;
    Ok(())
}

fn write_staging_recovery(organization: &str, input_set_id: &str) -> anyhow::Result<()> {
    writeln!(
        io::stderr().lock(),
        "error: Run Input Set preparation was interrupted"
    )?;
    write_staging_guidance(organization, input_set_id)
}

fn write_create_unknown(
    deployment: &str,
    organization: &str,
    input_set_id: Option<&str>,
    key: Option<&str>,
    json: bool,
    exit_code: ExitCode,
) -> anyhow::Result<ExitCode> {
    if json {
        if let Some(input_set_id) = input_set_id {
            write_staging_guidance(organization, input_set_id)?;
        }
        return write_cloud!(
            "create",
            deployment,
            organization,
            &CloudSnapshot::default(),
            "acceptance_unknown",
            Some("acceptance_unknown"),
            key,
            None,
            true,
            exit_code,
        );
    } else {
        writeln!(
            io::stderr().lock(),
            "error: run acceptance is unknown after interruption\n\norganization: {organization}\ninput set: {}\nidempotency key: {}\ncommitment: unknown\n\nReconcile this key with the deployment before creating another run.",
            input_set_id.unwrap_or("none"),
            key.unwrap_or("not established")
        )?;
    }
    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, mpsc};

    use super::*;
    use useful_api::{
        HttpClient, HttpTransportPolicy, InputScalarMetadata, NamedInputMetadata, RunApi,
        RunCreationAcceptance, RunFailure, RunInputManifest,
    };

    fn dispatch_test_api<'a>(api_url: &str, client: &'a HttpClient) -> RunApi<'a> {
        RunApi::new(
            api_url,
            "test-token",
            HttpTransportPolicy::AllowInsecureHttp,
            client,
        )
        .unwrap()
    }

    fn create_dispatch_test_run(
        api: &RunApi<'_>,
        begin_dispatch: impl Fn() -> bool,
    ) -> Result<RunCreationAcceptance, RunFailure> {
        api.create(
            "acme-research",
            "create-run-key",
            CreateRunInput {
                project_id: "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
                definition: RunDefinitionSelection::new(
                    "def_01k0z6r1w8f4jy2m7q9v3x5abc".to_owned(),
                ),
                source_branch: None,
                workspace_branch: None,
                workspace_commit: None,
                display_name: None,
                input_set_id: Some("ris_explicit"),
                integration_context: None,
                maximum_parallel_steps: None,
                unowned: false,
            },
            begin_dispatch,
        )
    }

    fn assert_interrupted<T>(result: Result<T, RunFailure>) {
        assert!(matches!(result, Err(RunFailure::Interrupted)));
    }

    fn assert_no_pending_request(listener: &TcpListener) {
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn create_signal_snapshot_preserves_dispatch_and_input_set_provenance() {
        let allocated = crate::cli::OperationControl::new(CreateRecoveryState::new(None));
        assert!(
            allocated.begin_dispatch_with_recovery(
                CreateRecoveryState::input_set_allocation_dispatched()
            )
        );
        assert!(
            allocated.update_recovery(CreateRecoveryState::allocated_input_set("ris_allocated"))
        );
        let snapshot = allocated.claim_signal().unwrap();
        assert_eq!(
            create_signal_recovery(snapshot),
            CreateSignalRecovery::InputSet("ris_allocated".to_owned())
        );
        assert!(!allocated.begin_dispatch());

        let explicit =
            crate::cli::OperationControl::new(CreateRecoveryState::new(Some("ris_explicit")));
        assert!(explicit.begin_dispatch_with_recovery(explicit.recovery().run_dispatched()));
        let snapshot = explicit.claim_signal().unwrap();
        assert_eq!(
            snapshot.recovery,
            CreateRecoveryState::RunDispatched(
                Some(CreateInputSetOwnership::Explicit("ris_explicit".to_owned())),
                None
            )
        );
        assert_eq!(
            create_signal_recovery(snapshot),
            CreateSignalRecovery::Run(Some("ris_explicit".to_owned()), None)
        );

        let inputless = crate::cli::OperationControl::new(CreateRecoveryState::new(None));
        assert!(inputless.begin_dispatch_with_recovery(inputless.recovery().run_dispatched()));
        assert_eq!(
            create_signal_recovery(inputless.claim_signal().unwrap()),
            CreateSignalRecovery::Run(None, None)
        );
    }

    fn assert_signal_before_dispatch_sends_no_request<T: Send>(
        recovery: CreateRecoveryState,
        dispatch_recovery: CreateRecoveryState,
        operation: impl FnOnce(&RunApi<'_>, &dyn Fn() -> bool) -> Result<T, RunFailure> + Send,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let api_url = format!("http://{}", listener.local_addr().unwrap());
        let control = Arc::new(crate::cli::OperationControl::new(recovery));
        let before_claim = Arc::new(Barrier::new(2));
        let release_claim = Arc::new(Barrier::new(2));

        std::thread::scope(|scope| {
            let worker_control = Arc::clone(&control);
            let worker_before_claim = Arc::clone(&before_claim);
            let worker_release_claim = Arc::clone(&release_claim);
            let worker = scope.spawn(move || {
                let client = HttpClient::new(HttpTransportPolicy::AllowInsecureHttp).unwrap();
                let api = dispatch_test_api(&api_url, &client);
                let begin_dispatch = || {
                    worker_before_claim.wait();
                    worker_release_claim.wait();
                    worker_control.begin_dispatch_with_recovery(dispatch_recovery.clone())
                };
                operation(&api, &begin_dispatch)
            });

            before_claim.wait();
            let snapshot = control.claim_signal().unwrap();
            assert!(!snapshot.dispatched);
            release_claim.wait();
            assert_interrupted(worker.join().unwrap());
        });

        assert_no_pending_request(&listener);
    }

    #[test]
    fn cancellation_wins_at_real_run_and_input_set_dispatch_boundaries() {
        assert_signal_before_dispatch_sends_no_request(
            CreateRecoveryState::new(Some("ris_explicit")),
            CreateRecoveryState::new(Some("ris_explicit")).run_dispatched(),
            |api, begin_dispatch| create_dispatch_test_run(api, begin_dispatch),
        );

        let manifest = RunInputManifest {
            inputs: BTreeMap::from([(
                "request".to_owned(),
                NamedInputMetadata::Text(InputScalarMetadata {
                    size_bytes: 0,
                    sha256: ring::digest::digest(&ring::digest::SHA256, b"")
                        .as_ref()
                        .try_into()
                        .unwrap(),
                }),
            )]),
        };
        assert_signal_before_dispatch_sends_no_request(
            CreateRecoveryState::new(None),
            CreateRecoveryState::input_set_allocation_dispatched(),
            |api, begin_dispatch| {
                api.create_input_set(
                    "acme-research",
                    "create-input-set-key",
                    "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
                    &manifest,
                    begin_dispatch,
                )
            },
        );
    }

    #[test]
    fn cancellation_blocks_a_run_create_transport_retry_after_dispatch() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_listener = listener.try_clone().unwrap();
        let api_url = format!("http://{}", listener.local_addr().unwrap());
        let control = Arc::new(crate::cli::OperationControl::new(CreateRecoveryState::new(
            Some("ris_explicit"),
        )));
        let (retry_ready, observe_retry) = mpsc::sync_channel(0);
        let (release_retry, retry_released) = mpsc::sync_channel(0);

        std::thread::scope(|scope| {
            let server = scope.spawn(move || {
                let (mut stream, _) = server_listener.accept().unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.starts_with("POST "));
                while line != "\r\n" {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                }
                drop(reader);
                stream
                    .write_all(
                        b"HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nIdempotency-Key: create-run-key\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{",
                    )
                    .unwrap();
            });

            let worker_control = Arc::clone(&control);
            let worker = scope.spawn(move || {
                let client = HttpClient::new(HttpTransportPolicy::AllowInsecureHttp).unwrap();
                let api = dispatch_test_api(&api_url, &client);
                let dispatches = AtomicUsize::new(0);
                let dispatch_recovery = worker_control.recovery().run_dispatched();
                create_dispatch_test_run(&api, || {
                    if dispatches.fetch_add(1, Ordering::AcqRel) == 1 {
                        retry_ready.send(()).unwrap();
                        retry_released.recv().unwrap();
                    }
                    worker_control.begin_dispatch_with_recovery(dispatch_recovery.clone())
                })
            });

            observe_retry.recv().unwrap();
            let snapshot = control.claim_signal().unwrap();
            assert_eq!(
                create_signal_recovery(snapshot),
                CreateSignalRecovery::Run(Some("ris_explicit".to_owned()), None)
            );
            release_retry.send(()).unwrap();
            assert_interrupted(worker.join().unwrap());
            server.join().unwrap();
        });

        listener.set_nonblocking(true).unwrap();
        assert_no_pending_request(&listener);
    }
}
