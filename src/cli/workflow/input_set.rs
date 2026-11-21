//! `useful workflow input-set` (REQ-RUNINPUT-61): a Cloud run's inputs, staged by hand before
//! the run exists, in the organization in effect and, for `create`, the project in effect
//! (REQ-ORG-87, REQ-PROJECT-100, INV-CLI-20). The leaves share the Cloud run helpers of
//! `src/cli/workflow/run/cloud_api.rs`, and `useful workflow run create` stages its named
//! inputs through [`stage_and_seal`].

use std::ffi::OsString;
use std::io::{self, Write};

use anyhow::Context as _;
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::exit_code::{ExitCode, OutcomeClass};
use useful_api::{
    CommonOrganizationFailure, RunFailure, RunInputSet, RunInputUpload, RunInputUploadOutcome,
    input_set_is_open, input_set_state_name,
};
use useful_human_auth::Deployment;

use super::super::context::{self, ContextFailure, OrgArgs, ProjectArgs, ProjectSubject};
use super::super::{
    CommandFailure, CommandResult, CommonArgs, NamedInputArgs, OperationControl,
    PrincipalAuthenticationArgs, PrincipalAuthenticationKind, SignalSnapshot, WorkflowJson,
};
use super::run::cloud_api::acquisition::{self, AcquiredInputs};
use super::run::cloud_api::{
    finish_operation, with_api, write_api_outcome, write_failure_with_input_set, write_json,
    write_resource_mutation_unknown,
};
use super::run::write_input_acquisition_failure;

pub(super) const ABOUT: &str = "Stage a Cloud run's inputs by hand before the run exists";
const GROUP: &str = "input-set";

/// The options every input-set leaf takes: the `workflow` family's `--json`, with the
/// credential and transport options of a Cloud request.
type Options = CommonArgs<WorkflowJson, PrincipalAuthenticationArgs>;

macro_rules! require_run_success {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(failure) => return Ok(Err(failure)),
        }
    };
}

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<InputSetCommand>,
}

#[derive(Debug, Subcommand)]
enum InputSetCommand {
    #[command(
        about = "Declare an input set's values",
        after_help = "Lifecycle:\n  Creation fixes the manifest and each member's content. While open, the set accepts matching uploads; sealing verifies every declared member."
    )]
    Create(CreateCommand),
    #[command(
        about = "Delete an input set",
        after_help = "Deletion:\n  The Run Input Set becomes logically unavailable; content cleanup is scheduled."
    )]
    Delete(DeleteCommand),
    #[command(
        about = "Seal an input set so runs can use it",
        after_help = "Eligibility:\n  Upload the declared members to an open Run Input Set before sealing it."
    )]
    Seal(SealCommand),
    #[command(about = "Show an input set and its members")]
    Show(ShowCommand),
    #[command(
        about = "Upload a file to an open input set",
        after_help = "Eligibility:\n  The Run Input Set must still be open for uploads."
    )]
    Upload(UploadCommand),
}

// Input-set creation and runner-pool creation share only generic CLI shape; their
// project/input and pool-name operations remain clearer as separate command types.
#[derive(Debug, Args)]
struct CreateCommand {
    #[command(flatten)]
    inputs: NamedInputArgs,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    project: ProjectArgs,

    #[command(flatten)]
    options: Options,
}

/// The `INPUT_SET` a leaf acts on and `--org`, the organization in effect it is read in.
#[derive(Debug, Args)]
struct InputSetArgs {
    #[arg(
        value_name = "INPUT_SET",
        value_parser = parse_input_set_id,
        help = "Run Input Set ID"
    )]
    input_set_id: String,

    #[command(flatten)]
    org: OrgArgs,
}

impl InputSetArgs {
    /// Runs `run` with `options` and the set in the organization in effect (REQ-ORG-87): the
    /// organization is resolved before the leaf's first request and its signal handling, and a
    /// refused read of the memberships is written as this family's failure.
    fn execute_in(
        self,
        options: Options,
        deployment: &Deployment,
        run: impl FnOnce(Options, InputSetReference) -> CommandResult,
    ) -> CommandResult {
        let Self { input_set_id, org } = self;
        context::execute_in_keeping_exit(
            org,
            options,
            deployment,
            |deployment, failure, authentication, json| {
                write_context_failure(deployment, &refused(failure), authentication, json)
            },
            |options, organization| {
                run(
                    options,
                    InputSetReference {
                        organization: organization.to_owned(),
                        input_set_id,
                    },
                )
            },
        )
    }
}

/// An input set in the organization a leaf resolved: the reference it sends, the value `--org`
/// or `USEFUL_ORG` gave or else the organization's ID, and the set's ID.
#[derive(Clone, Debug)]
struct InputSetReference {
    organization: String,
    input_set_id: String,
}

impl InputSetReference {
    fn get(
        &self,
        deployment: &Deployment,
        options: &Options,
    ) -> anyhow::Result<Result<RunInputSet, RunFailure>> {
        with_api(
            deployment,
            options.http.transport_policy(),
            &options.authentication,
            |api| api.get_input_set(&self.organization, &self.input_set_id),
        )
    }

    fn get_open(
        &self,
        deployment: &Deployment,
        options: &Options,
    ) -> anyhow::Result<Result<RunInputSet, RunFailure>> {
        Ok(match self.get(deployment, options)? {
            Ok(input_set) if input_set_is_open(&input_set) => Ok(input_set),
            Ok(_) => Err(RunFailure::Conflict),
            Err(failure) => Err(failure),
        })
    }
}

#[derive(Debug, Args)]
struct ShowCommand {
    #[command(flatten)]
    input_set: InputSetArgs,

    #[command(flatten)]
    options: Options,
}

#[derive(Debug, Args)]
struct UploadCommand {
    #[command(flatten)]
    input_set: InputSetArgs,

    #[arg(
        long = "member-file",
        value_names = ["MEMBER", "PATH"],
        num_args = 2,
        action = clap::ArgAction::Append,
        required = true,
        help = "Upload a regular file as one exact logical member"
    )]
    member_files: Vec<OsString>,

    #[command(flatten)]
    options: Options,
}

#[derive(Debug, Args)]
struct SealCommand {
    #[command(flatten)]
    input_set: InputSetArgs,

    #[command(flatten)]
    options: Options,
}

// Keep this leaf's reference and confirmation wording explicit: Run Input Set deletion
// and retained-content deletion are distinct destructive contracts in CLI help.
#[derive(Debug, Args)]
struct DeleteCommand {
    #[command(flatten)]
    input_set: InputSetArgs,

    #[command(flatten)]
    confirmation: super::super::ConfirmationArgs,

    #[command(flatten)]
    options: Options,
}

impl Command {
    pub(super) fn execute(self) -> CommandResult {
        match self.command {
            None => super::super::print_help(&[super::NAME, GROUP]),
            Some(InputSetCommand::Create(command)) => execute_deployed(
                command,
                "configure Run Input Set creation",
                CreateCommand::execute,
            ),
            Some(InputSetCommand::Show(command)) => execute_deployed(
                command,
                "configure Run Input Set access",
                ShowCommand::execute,
            ),
            Some(InputSetCommand::Upload(command)) => execute_deployed(
                command,
                "configure Run Input Set upload",
                UploadCommand::execute,
            ),
            Some(InputSetCommand::Seal(command)) => execute_deployed(
                command,
                "configure Run Input Set sealing",
                SealCommand::execute,
            ),
            Some(InputSetCommand::Delete(command)) => execute_deployed(
                command,
                "configure Run Input Set deletion",
                DeleteCommand::execute,
            ),
        }
    }
}

fn execute_deployed<T>(
    command: T,
    context: &'static str,
    operation: impl FnOnce(T, &Deployment) -> CommandResult,
) -> CommandResult {
    super::super::execute_deployment_command(
        Some(command),
        &[super::NAME, GROUP],
        context,
        operation,
    )
}

/// A refused read of the memberships or projects that name the organization and the project in
/// effect, as the run outcome that names the same refusal.
const fn refused(failure: &CommonOrganizationFailure) -> RunFailure {
    match failure {
        CommonOrganizationFailure::Unauthenticated => RunFailure::Unauthenticated,
        CommonOrganizationFailure::Forbidden => RunFailure::Forbidden,
        CommonOrganizationFailure::InvalidInput => RunFailure::InvalidInput,
        CommonOrganizationFailure::Unreachable(category) => RunFailure::Unreachable(*category),
    }
}

/// The family's one writer for a failed read of the organization or the project a leaf acts
/// in: the run failure document, with no `organizationRef`, since none was resolved.
fn write_context_failure(
    deployment: &str,
    failure: &RunFailure,
    authentication: PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    write_failure_with_input_set(deployment, "", None, None, failure, authentication, json)
}

impl CreateCommand {
    fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self {
            inputs,
            org,
            project,
            options,
        } = self;
        // A failure the creation ends with keeps its exit code through the context's
        // `anyhow` result.
        let mut ended = None;
        let exit_code = context::execute_in_project(
            org,
            ProjectSubject::InEffect(project),
            options,
            deployment,
            |deployment, failure, authentication, json| {
                let failure = match failure {
                    ContextFailure::Refused(failure) => refused(failure),
                    ContextFailure::UnknownProject => RunFailure::NotFound,
                };
                write_context_failure(deployment, &failure, authentication, json)
            },
            |options, organization, project| {
                let creation = Creation {
                    inputs,
                    organization: organization.to_owned(),
                    project_id: project.to_owned(),
                    options,
                };
                creation.execute(deployment.clone()).or_else(|failure| {
                    let exit_code = failure.exit_code();
                    ended = Some(failure);
                    Ok(exit_code)
                })
            },
        )?;
        ended.map_or(Ok(exit_code), Err)
    }
}

/// A `create` in the organization and the project it resolved.
struct Creation {
    inputs: NamedInputArgs,
    organization: String,
    project_id: String,
    options: Options,
}

impl Creation {
    fn execute(self, deployment: Deployment) -> Result<ExitCode, CommandFailure> {
        let signal_deployment = deployment.clone();
        let signal_organization = self.organization.clone();
        let signal_json = self.options.json;
        super::super::execute_mutation_with_signals(
            "Run Input Set creation",
            None::<String>,
            move |control| {
                let Some(acquired) = acquire_required_inputs(
                    &self.inputs,
                    deployment.fingerprint().api_url(),
                    &self.organization,
                    "at least one named input is required",
                    self.options.json,
                    self.options.authentication.uses_stdin(),
                    control,
                )?
                else {
                    return Ok(ExitCode::GeneralFailure);
                };
                if control.is_cancelled() {
                    return Ok(ExitCode::GeneralFailure);
                }
                let result = create_input_set(
                    &deployment,
                    self.options.http.transport_policy(),
                    &self.options.authentication,
                    &self.organization,
                    &self.project_id,
                    &acquired,
                    || control.begin_dispatch(),
                )?;
                if let Ok(input_set) = &result {
                    control.update_recovery(Some(input_set.id.clone()));
                }
                let input_set_id = control.recovery();
                // Creation reports an allocated input-set coordinate rather than the retained-run
                // coordinate used by input deletion; each recovery envelope stays explicit.
                finish_operation(control, || {
                    write_result(
                        deployment.fingerprint().api_url(),
                        &self.organization,
                        input_set_id.as_deref(),
                        "created",
                        result,
                        self.options.authentication.kind(),
                        self.options.json,
                    )
                })
            },
            move |signal, snapshot| {
                super::super::report_dispatched_signal(
                    signal,
                    snapshot,
                    |recovery| match recovery {
                        Some(input_set_id) => write_input_set_recovery(
                            signal_deployment.fingerprint().api_url(),
                            &signal_organization,
                            &input_set_id,
                            signal_json,
                            signal,
                        )
                        .map_err(Into::into),
                        None => write_resource_mutation_unknown(
                            "Run Input Set creation",
                            signal_deployment.fingerprint().api_url(),
                            &signal_organization,
                            "input set",
                            None,
                            signal_json,
                            signal,
                        )
                        .map_err(Into::into),
                    },
                )
            },
        )
    }
}

fn create_input_set(
    deployment: &Deployment,
    transport_policy: useful_api::HttpTransportPolicy,
    authentication: &PrincipalAuthenticationArgs,
    organization: &str,
    project_id: &str,
    acquired: &AcquiredInputs,
    begin_dispatch: impl Fn() -> bool,
) -> anyhow::Result<Result<RunInputSet, RunFailure>> {
    let create_key = useful_support::generate_idempotency_key()
        .context("generate Run Input Set request identity")?;
    with_api(deployment, transport_policy, authentication, |api| {
        api.create_input_set(
            organization,
            &create_key,
            project_id,
            &acquired.manifest,
            &begin_dispatch,
        )
    })
}

fn report_input_set_recovery(
    signal: ExitCode,
    snapshot: SignalSnapshot<()>,
    deployment: &Deployment,
    input_set: &InputSetReference,
    json: bool,
) -> CommandResult {
    super::super::report_dispatched_signal(signal, snapshot, |()| {
        write_input_set_recovery(
            deployment.fingerprint().api_url(),
            &input_set.organization,
            &input_set.input_set_id,
            json,
            signal,
        )
        .map_err(Into::into)
    })
}

fn report_input_set_mutation_unknown(
    signal: ExitCode,
    snapshot: SignalSnapshot<()>,
    operation: &'static str,
    deployment: &Deployment,
    input_set: &InputSetReference,
    json: bool,
) -> CommandResult {
    super::super::report_dispatched_signal(signal, snapshot, |()| {
        write_resource_mutation_unknown(
            operation,
            deployment.fingerprint().api_url(),
            &input_set.organization,
            "input set",
            Some(&input_set.input_set_id),
            json,
            signal,
        )
        .map_err(Into::into)
    })
}

/// The recovery state of a command that stages an input set as one step of its own operation,
/// as `useful workflow run create` does in `src/cli/workflow/run/create/cloud.rs`: what a
/// signal reports while the set's creation is dispatched, and once the set exists.
pub(in crate::cli::workflow) trait StagingRecovery {
    fn input_set_allocation_dispatched() -> Self;
    fn allocated_input_set(input_set_id: &str) -> Self;
}

/// Creates, uploads and seals the input set `workflow run create` stages from its named inputs,
/// in the organization and the project that command resolved.
pub(in crate::cli::workflow) fn stage_and_seal<R: StagingRecovery>(
    deployment: &Deployment,
    transport_policy: useful_api::HttpTransportPolicy,
    authentication: &PrincipalAuthenticationArgs,
    organization: &str,
    project_id: &str,
    acquired: &AcquiredInputs,
    control: &OperationControl<R>,
) -> anyhow::Result<Result<RunInputSet, RunFailure>> {
    let seal_key = useful_support::generate_idempotency_key()
        .context("generate Run Input Set seal identity")?;
    let input_set = match create_input_set(
        deployment,
        transport_policy,
        authentication,
        organization,
        project_id,
        acquired,
        || control.begin_dispatch_with_recovery(R::input_set_allocation_dispatched()),
    )? {
        Ok(input_set) => input_set,
        Err(failure) => return Ok(Err(failure)),
    };
    control.update_recovery(R::allocated_input_set(&input_set.id));
    if control.is_cancelled() {
        return Ok(Err(RunFailure::Interrupted));
    }
    let uploads = acquired
        .objects
        .iter()
        .map(acquisition::AcquiredInputObject::upload)
        .collect::<Vec<RunInputUpload<'_>>>();
    if let Err(failure) = with_api(deployment, transport_policy, authentication, |api| {
        api.upload_input_members(organization, &input_set, &uploads, || {
            control.begin_dispatch()
        })
    })? {
        return Ok(Err(failure));
    }
    if control.is_cancelled() {
        return Ok(Err(RunFailure::Interrupted));
    }
    with_api(deployment, transport_policy, authentication, |api| {
        api.seal_input_set(organization, &seal_key, &input_set, || {
            control.begin_dispatch()
        })
    })
}

impl ShowCommand {
    fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self { input_set, options } = self;
        input_set.execute_in(options, deployment, |options, input_set| {
            let deployment = deployment.clone();
            super::super::execute_read_only_with_signals("Run Input Set show", move |control| {
                let result = input_set.get(&deployment, &options)?;
                super::super::complete_read_only_output(control, || {
                    write_result(
                        deployment.fingerprint().api_url(),
                        &input_set.organization,
                        Some(&input_set.input_set_id),
                        "found",
                        result,
                        options.authentication.kind(),
                        options.json,
                    )
                    .map_err(Into::into)
                })
            })
        })
    }
}

impl UploadCommand {
    fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self {
            input_set,
            member_files,
            options,
        } = self;
        input_set.execute_in(options, deployment, |options, input_set| {
            let deployment = deployment.clone();
            let signal_deployment = deployment.clone();
            let signal_input_set = input_set.clone();
            let signal_json = options.json;
            super::super::execute_mutation_with_signals(
                "Run Input Set upload",
                (),
                move |control| {
                    let acquired = match acquisition::acquire_member_files(&member_files) {
                        Ok(acquired) => acquired,
                        Err(failure) => {
                            return finish_operation(control, || {
                                write_input_acquisition_failure(
                                    deployment.fingerprint().api_url(),
                                    &input_set.organization,
                                    &failure,
                                    options.json,
                                )
                            });
                        }
                    };
                    let result =
                        upload_selected(&deployment, &input_set, &options, &acquired, control)?;
                    finish_operation(control, || {
                        write_upload_result(
                            deployment.fingerprint().api_url(),
                            &input_set.organization,
                            &input_set.input_set_id,
                            result,
                            options.authentication.kind(),
                            options.json,
                        )
                    })
                },
                move |signal, snapshot| {
                    report_input_set_recovery(
                        signal,
                        snapshot,
                        &signal_deployment,
                        &signal_input_set,
                        signal_json,
                    )
                },
            )
        })
    }
}

fn upload_selected(
    deployment: &Deployment,
    input_set: &InputSetReference,
    options: &Options,
    acquired: &[acquisition::AcquiredInputObject],
    control: &OperationControl<()>,
) -> anyhow::Result<Result<RunInputUploadOutcome, RunFailure>> {
    let open = require_run_success!(input_set.get_open(deployment, options)?);
    let uploads = acquired
        .iter()
        .map(acquisition::AcquiredInputObject::upload)
        .collect::<Vec<RunInputUpload<'_>>>();
    with_api(
        deployment,
        options.http.transport_policy(),
        &options.authentication,
        |api| {
            api.upload_input_members(&input_set.organization, &open, &uploads, || {
                control.begin_dispatch()
            })
        },
    )
}

impl SealCommand {
    fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self { input_set, options } = self;
        input_set.execute_in(options, deployment, |options, input_set| {
            let deployment = deployment.clone();
            let signal_deployment = deployment.clone();
            let signal_input_set = input_set.clone();
            let signal_json = options.json;
            super::super::execute_mutation_with_signals(
                "Run Input Set sealing",
                (),
                move |control| {
                    let result = seal(&deployment, &input_set, &options, control)?;
                    // Sealing and deletion have distinct success bodies and recovery semantics
                    // even though both complete through the shared mutation control.
                    finish_operation(control, || {
                        write_result(
                            deployment.fingerprint().api_url(),
                            &input_set.organization,
                            Some(&input_set.input_set_id),
                            "sealed",
                            result,
                            options.authentication.kind(),
                            options.json,
                        )
                    })
                },
                move |signal, snapshot| {
                    report_input_set_mutation_unknown(
                        signal,
                        snapshot,
                        "Run Input Set sealing",
                        &signal_deployment,
                        &signal_input_set,
                        signal_json,
                    )
                },
            )
        })
    }
}

fn seal(
    deployment: &Deployment,
    input_set: &InputSetReference,
    options: &Options,
    control: &OperationControl<()>,
) -> anyhow::Result<Result<RunInputSet, RunFailure>> {
    let open = require_run_success!(input_set.get_open(deployment, options)?);
    let key = useful_support::generate_idempotency_key()
        .context("generate Run Input Set seal identity")?;
    with_api(
        deployment,
        options.http.transport_policy(),
        &options.authentication,
        |api| {
            api.seal_input_set(&input_set.organization, &key, &open, || {
                control.begin_dispatch()
            })
        },
    )
}

impl DeleteCommand {
    fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self {
            input_set,
            confirmation: _,
            options,
        } = self;
        input_set.execute_in(options, deployment, |options, input_set| {
            let deployment = deployment.clone();
            let key = useful_support::generate_idempotency_key()
                .context("generate Run Input Set deletion identity")?;
            let signal_deployment = deployment.clone();
            let signal_input_set = input_set.clone();
            let signal_json = options.json;
            super::super::execute_mutation_with_signals(
                "Run Input Set deletion",
                (),
                move |control| {
                    // Input Set deletion and retained-input deletion deliberately keep separate
                    // recovery subjects and output envelopes.
                    let result = with_api(
                        &deployment,
                        options.http.transport_policy(),
                        &options.authentication,
                        |api| {
                            api.delete_input_set(
                                &input_set.organization,
                                &input_set.input_set_id,
                                &key,
                                || control.begin_dispatch(),
                            )
                        },
                    )?;
                    finish_operation(control, || {
                        write_mutation_result(
                            deployment.fingerprint().api_url(),
                            &input_set.organization,
                            &input_set.input_set_id,
                            "deleted",
                            result,
                            options.authentication.kind(),
                            options.json,
                        )
                    })
                },
                move |signal, snapshot| {
                    report_input_set_mutation_unknown(
                        signal,
                        snapshot,
                        "Run Input Set deletion",
                        &signal_deployment,
                        &signal_input_set,
                        signal_json,
                    )
                },
            )
        })
    }
}

fn write_result(
    deployment: &str,
    organization: &str,
    input_set_id: Option<&str>,
    outcome: &'static str,
    result: Result<RunInputSet, RunFailure>,
    authentication: PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    match result {
        Ok(input_set) => {
            if json {
                write_json(&InputSetResult {
                    schema_version: 1,
                    deployment,
                    outcome,
                    input_set: &input_set,
                })?;
            } else {
                let mut stdout = io::stdout().lock();
                writeln!(
                    stdout,
                    "✓ Run Input Set {}.",
                    input_set_state_name(&input_set)
                )?;
                writeln!(stdout, "\ninput set: {}", input_set.id)?;
                writeln!(stdout, "project: {}", input_set.project_id)?;
                writeln!(stdout, "state: {}", input_set_state_name(&input_set))?;
                writeln!(stdout, "inputs: {}", input_set.manifest.inputs.len())?;
                writeln!(
                    stdout,
                    "manifest digest: {}",
                    input_set.manifest_digest.value
                )?;
                writeln!(stdout, "organization: {organization}")?;
                writeln!(stdout, "deployment: {deployment}")?;
            }
            Ok(ExitCode::Success)
        }
        Err(failure) => write_input_set_failure(
            deployment,
            organization,
            input_set_id,
            &failure,
            authentication,
            json,
        ),
    }
}

fn write_upload_result(
    deployment: &str,
    organization: &str,
    input_set_id: &str,
    result: Result<RunInputUploadOutcome, RunFailure>,
    authentication: PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    write_input_set_outcome(
        deployment,
        organization,
        Some(input_set_id),
        result,
        authentication,
        json,
        |upload| {
            let verification_required = upload.verification_required_members > 0;
            let outcome = if verification_required {
                "verification_required"
            } else {
                "uploaded"
            };
            if json {
                write_json(&UploadResult {
                    schema_version: 1,
                    deployment,
                    outcome,
                    organization_ref: organization,
                    input_set_id,
                    accepted_members: upload.accepted_members,
                    verification_required_members: upload.verification_required_members,
                })?;
            } else {
                writeln!(
                    io::stdout().lock(),
                    "✓ Run Input Set upload finished.\n\ninput set: {input_set_id}\naccepted members: {}\nverification required members: {}\norganization: {organization}\ndeployment: {deployment}{}",
                    upload.accepted_members,
                    upload.verification_required_members,
                    if verification_required {
                        "\n\nSeal this input set to verify members reported as already present."
                    } else {
                        ""
                    }
                )?;
            }
            Ok(())
        },
    )
}

// Deletion has an empty success value and a mutation receipt; upload keeps member counts and a
// verification-required outcome, so explicit closures make the two result contracts reviewable.
fn write_mutation_result(
    deployment: &str,
    organization: &str,
    input_set_id: &str,
    outcome: &'static str,
    result: Result<(), RunFailure>,
    authentication: PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    write_input_set_outcome(
        deployment,
        organization,
        Some(input_set_id),
        result,
        authentication,
        json,
        |()| {
            if json {
                write_json(&MutationResult {
                    schema_version: 1,
                    deployment,
                    outcome,
                    organization_ref: organization,
                    input_set_id,
                })?;
            } else {
                writeln!(
                    io::stdout().lock(),
                    "✓ Run Input Set made logically unavailable; content cleanup scheduled.\n\ninput set: {input_set_id}\norganization: {organization}\ndeployment: {deployment}"
                )?;
            }
            Ok(())
        },
    )
}

fn write_input_set_outcome<T>(
    deployment: &str,
    organization: &str,
    input_set_id: Option<&str>,
    result: Result<T, RunFailure>,
    authentication: PrincipalAuthenticationKind,
    json: bool,
    write_success: impl FnOnce(T) -> anyhow::Result<()>,
) -> anyhow::Result<ExitCode> {
    write_api_outcome(result, write_success, |failure| {
        write_input_set_failure(
            deployment,
            organization,
            input_set_id,
            failure,
            authentication,
            json,
        )
    })
}

fn write_input_set_failure(
    deployment: &str,
    organization: &str,
    input_set_id: Option<&str>,
    failure: &RunFailure,
    authentication: PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    write_failure_with_input_set(
        deployment,
        organization,
        None,
        input_set_id,
        failure,
        authentication,
        json,
    )
}

fn acquire_required_inputs<R>(
    arguments: &NamedInputArgs,
    deployment: &str,
    organization: &str,
    empty_diagnostic: &str,
    json: bool,
    service_api_key_from_stdin: bool,
    control: &OperationControl<R>,
) -> Result<Option<AcquiredInputs>, CommandFailure> {
    if let Err(failure) =
        acquisition::validate_standard_input_claims(arguments, None, service_api_key_from_stdin)
    {
        finish_operation(control, || {
            write_input_acquisition_failure(deployment, organization, &failure, json)
        })?;
        return Ok(None);
    }
    match acquisition::acquire(arguments) {
        Ok(acquired) if !acquired.manifest.inputs.is_empty() => Ok(Some(acquired)),
        Ok(_) => {
            finish_operation(control, || {
                write_local_failure(deployment, organization, empty_diagnostic, json)
            })?;
            Ok(None)
        }
        Err(failure) => {
            finish_operation(control, || {
                write_input_acquisition_failure(deployment, organization, &failure, json)
            })?;
            Ok(None)
        }
    }
}

/// A Run Input Set ID, exactly: `--input-set` of `useful workflow run create` and the leaves of
/// `useful workflow input-set` take one.
pub(in crate::cli::workflow) fn parse_input_set_id(value: &str) -> Result<String, String> {
    if useful_support::valid_typed_id(value, "ris_") {
        Ok(value.to_owned())
    } else {
        Err(
            "must be an exact Run Input Set ID (ris_ followed by 26 lowercase ULID characters)"
                .to_owned(),
        )
    }
}

fn write_input_set_recovery(
    deployment: &str,
    organization: &str,
    input_set_id: &str,
    json: bool,
    exit_code: ExitCode,
) -> anyhow::Result<ExitCode> {
    if json {
        write_json(&InputSetRecoveryResult {
            schema_version: 1,
            deployment,
            outcome: "input_set_incomplete",
            organization_ref: organization,
            input_set_id,
        })?;
    } else {
        writeln!(
            io::stderr().lock(),
            "error: Run Input Set preparation was interrupted\n\ninput set: {input_set_id}\norganization: {organization}\n\nInspect and resume this input set explicitly before creating another set."
        )?;
    }
    Ok(exit_code)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InputSetRecoveryResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    organization_ref: &'a str,
    input_set_id: &'a str,
}

fn write_local_failure(
    deployment: &str,
    organization: &str,
    diagnostic: &str,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        write_json(&MutationResult {
            schema_version: 1,
            deployment,
            outcome: "invalid_input",
            organization_ref: organization,
            input_set_id: "",
        })?;
    } else {
        writeln!(io::stderr().lock(), "error: {diagnostic}")?;
    }
    Ok(OutcomeClass::GeneralFailure.exit_code())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InputSetResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    input_set: &'a RunInputSet,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UploadResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    organization_ref: &'a str,
    input_set_id: &'a str,
    accepted_members: usize,
    verification_required_members: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MutationResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    organization_ref: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    input_set_id: &'a str,
}
