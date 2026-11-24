//! Webhook commands keep config acquisition ahead of all credential and Cloud I/O.
use super::{Options, OrgArgs, ProjectArgs, ProjectSubject};
use crate::exit_code::{ExitCode, OutcomeClass};
use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Args, Subcommand};
use serde_json::{Map, Value};
use std::{
    collections::HashSet,
    io::{self, Read},
    path::{Path, PathBuf},
};
use useful_api::{
    HttpClient, WebhookApi, WebhookDelivery, WebhookFailure, WebhookMutation, WebhookSubscription,
};
use useful_human_auth::Deployment;
use zeroize::Zeroizing;

type CommandResult = super::super::CommandResult;
#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<Leaf>,
}
#[derive(Debug, Subcommand)]
enum Leaf {
    #[command(about = "Create an enabled webhook subscription")]
    Create(Create),
    #[command(about = "Delete a webhook subscription")]
    Delete(Delete),
    #[command(about = "Manage webhook deliveries")]
    Delivery(DeliveryCommand),
    #[command(about = "Disable a webhook subscription")]
    Disable(Target),
    #[command(about = "Enable a webhook subscription")]
    Enable(Target),
    #[command(about = "List webhook subscriptions")]
    List(List),
    #[command(about = "Manage a webhook's signing secret")]
    Secret(SecretCommand),
    #[command(about = "Show subscription metadata")]
    Show(Target),
    #[command(about = "Queue a test delivery to a webhook")]
    Test(Target),
    #[command(about = "Replace selected filters or context keys")]
    Update(Update),
}
/// The organization and the project in effect every leaf acts in.
#[derive(Debug, Args)]
struct InEffect {
    #[command(flatten)]
    org: OrgArgs,
    #[command(flatten)]
    project: ProjectArgs,
}
impl InEffect {
    /// Runs `run` with the options, the organization reference to send and the project's ID.
    fn execute(
        self,
        options: Options,
        deployment: &Deployment,
        run: impl FnOnce(Options, &str, &str) -> anyhow::Result<ExitCode>,
    ) -> CommandResult {
        super::execute_in_project(
            self.org,
            ProjectSubject::InEffect(self.project),
            options,
            deployment,
            run,
        )
    }
}
#[derive(Debug, Args)]
struct Source {
    #[arg(
        long,
        value_name = "PATH",
        help = "Webhook config file (- for standard input)"
    )]
    config_file: PathBuf,
}
#[derive(Debug, Args)]
struct Create {
    #[command(flatten)]
    source: Source,
    #[command(flatten)]
    in_effect: InEffect,
    #[command(flatten)]
    options: Options,
}
#[derive(Debug, Args)]
struct Update {
    #[arg(value_name = "WEBHOOK")]
    webhook: String,
    #[command(flatten)]
    source: Source,
    #[arg(long, value_name = "VERSION", value_parser = clap::value_parser!(i64).range(1..), help = "Current subscription version")]
    expected_version: i64,
    #[command(flatten)]
    in_effect: InEffect,
    #[command(flatten)]
    options: Options,
}
#[derive(Debug, Args)]
struct Target {
    #[arg(value_name = "WEBHOOK")]
    webhook: String,
    #[command(flatten)]
    in_effect: InEffect,
    #[command(flatten)]
    options: Options,
}
#[derive(Debug, Args)]
struct Delete {
    #[command(flatten)]
    target: Target,
    #[command(flatten)]
    confirmation: super::super::ConfirmationArgs,
}
#[derive(Debug, Args)]
struct List {
    #[command(flatten)]
    page: super::super::PaginationArgs<100>,
    #[command(flatten)]
    in_effect: InEffect,
    #[command(flatten)]
    options: Options,
}
#[derive(Debug, Args)]
struct SecretCommand {
    #[command(subcommand)]
    command: Option<SecretLeaf>,
}
// `revoke` ends only the overlap of a secret a rotation already replaced, so it asks for no
// confirmation.
#[derive(Debug, Subcommand)]
enum SecretLeaf {
    #[command(about = "Stop accepting the secret the last rotation replaced")]
    Revoke(Target),
    #[command(about = "Replace the signing secret and show the new one once")]
    Rotate(Target),
}
#[derive(Debug, Args)]
struct DeliveryCommand {
    #[command(subcommand)]
    command: Option<DeliveryLeaf>,
}
#[derive(Debug, Subcommand)]
enum DeliveryLeaf {
    #[command(about = "List a webhook's deliveries")]
    List(DeliveryList),
    #[command(about = "Replay a webhook delivery")]
    Replay(DeliveryTarget),
    #[command(about = "Show a webhook delivery and its attempts")]
    Show(DeliveryTarget),
}
#[derive(Debug, Args)]
struct DeliveryList {
    #[arg(value_name = "WEBHOOK")]
    webhook: String,
    #[command(flatten)]
    page: super::super::PaginationArgs<100>,
    #[arg(long, value_name = "RUN")]
    run: Option<String>,
    #[arg(long, value_parser = ["queued", "in_flight", "succeeded", "failed", "cancelled"])]
    state: Option<String>,
    #[command(flatten)]
    in_effect: InEffect,
    #[command(flatten)]
    options: Options,
}
#[derive(Debug, Args)]
struct DeliveryTarget {
    #[arg(value_name = "DELIVERY")]
    delivery: String,
    #[arg(
        long,
        value_name = "WEBHOOK",
        help = "Webhook subscription ID the delivery belongs to"
    )]
    webhook: String,
    #[command(flatten)]
    in_effect: InEffect,
    #[command(flatten)]
    options: Options,
}

impl Command {
    pub(super) fn execute(self) -> CommandResult {
        match self.command {
            None => super::super::print_help(&["project", "webhook"]),
            Some(Leaf::Delivery(DeliveryCommand { command: None })) => {
                super::super::print_help(&["project", "webhook", "delivery"])
            }
            Some(Leaf::Secret(SecretCommand { command: None })) => {
                super::super::print_help(&["project", "webhook", "secret"])
            }
            Some(command) => super::execute_command(command, Leaf::execute),
        }
    }
}
impl Leaf {
    fn execute(self, deployment: &Deployment) -> CommandResult {
        match self {
            // The configuration is read and checked before the context is resolved, so a bad
            // file is `invalid_input` with no credential used and no request.
            Self::Create(cmd) => {
                let config = match acquire(
                    &cmd.source.config_file,
                    false,
                    cmd.options.authentication.uses_stdin(),
                ) {
                    Ok(config) => config,
                    Err(error) => {
                        return input_failure(deployment, &cmd.options, &error).map_err(Into::into);
                    }
                };
                cmd.in_effect
                    .execute(cmd.options, deployment, |options, organization, project| {
                        let key = key()?;
                        let result = call(deployment, &options, |api| {
                            Ok(api.mutate::<WebhookSubscription>(
                                WebhookMutation::Create,
                                organization,
                                project,
                                (None, None),
                                &key,
                                Some(&config),
                            ))
                        })?;
                        subscription_result(
                            deployment,
                            &options,
                            result,
                            "created",
                            true,
                            (None, project),
                            Some(MutationContext {
                                key: &key,
                                project,
                                webhook: None,
                                delivery: None,
                            }),
                        )
                    })
            }
            Self::Update(cmd) => {
                let mut config = match acquire(
                    &cmd.source.config_file,
                    true,
                    cmd.options.authentication.uses_stdin(),
                ) {
                    Ok(config) => config,
                    Err(error) => {
                        return input_failure(deployment, &cmd.options, &error).map_err(Into::into);
                    }
                };
                config.insert(
                    "expectedVersion".to_owned(),
                    Value::from(cmd.expected_version),
                );
                let webhook = cmd.webhook;
                cmd.in_effect
                    .execute(cmd.options, deployment, |options, organization, project| {
                        let key = key()?;
                        let result = call(deployment, &options, |api| {
                            Ok(api.mutate::<WebhookSubscription>(
                                WebhookMutation::Update,
                                organization,
                                project,
                                (Some(&webhook), None),
                                &key,
                                Some(&config),
                            ))
                        })?;
                        subscription_result(
                            deployment,
                            &options,
                            result,
                            "updated",
                            false,
                            (Some(&webhook), project),
                            Some(MutationContext {
                                key: &key,
                                project,
                                webhook: Some(&webhook),
                                delivery: None,
                            }),
                        )
                    })
            }
            Self::List(cmd) => {
                let page = cmd.page;
                cmd.in_effect
                    .execute(cmd.options, deployment, |options, organization, project| {
                        let result = call(deployment, &options, |api| {
                            Ok(api.subscriptions(
                                organization,
                                project,
                                page.limit,
                                page.cursor.as_deref(),
                            ))
                        })?;
                        match result {
                            Ok(page) => subscription_list_result(
                                deployment,
                                &options,
                                &page.items,
                                page.next_cursor.as_deref(),
                            ),
                            Err(failure) => failure_result(deployment, &options, failure),
                        }
                    })
            }
            Self::Show(cmd) => {
                let webhook = cmd.webhook;
                cmd.in_effect
                    .execute(cmd.options, deployment, |options, organization, project| {
                        let result = call(deployment, &options, |api| {
                            Ok(api.subscription(organization, project, &webhook))
                        })?;
                        subscription_result(
                            deployment,
                            &options,
                            result.map(Some),
                            "found",
                            false,
                            (Some(&webhook), project),
                            None,
                        )
                    })
            }
            Self::Enable(cmd) => change(deployment, cmd, WebhookMutation::Enable, "enabled"),
            Self::Disable(cmd) => change(deployment, cmd, WebhookMutation::Disable, "disabled"),
            Self::Delete(cmd) => change(deployment, cmd.target, WebhookMutation::Delete, "deleted"),
            Self::Secret(cmd) => match cmd.command {
                Some(SecretLeaf::Rotate(cmd)) => {
                    change(deployment, cmd, WebhookMutation::Rotate, "rotated")
                }
                Some(SecretLeaf::Revoke(cmd)) => {
                    change(deployment, cmd, WebhookMutation::Revoke, "revoked")
                }
                None => Err(anyhow!("secret subcommand missing after help dispatch").into()),
            },
            Self::Test(cmd) => queued_delivery(
                deployment,
                (cmd.webhook, None),
                cmd.in_effect,
                cmd.options,
                WebhookMutation::Test,
                "queued",
            ),
            Self::Delivery(cmd) => match cmd.command {
                Some(DeliveryLeaf::List(cmd)) => {
                    let DeliveryList {
                        webhook,
                        page,
                        run,
                        state,
                        in_effect,
                        options,
                    } = cmd;
                    in_effect.execute(options, deployment, |options, organization, project| {
                        let result = call(deployment, &options, |api| {
                            Ok(api.deliveries(
                                organization,
                                project,
                                &webhook,
                                page.limit,
                                page.cursor.as_deref(),
                                (run.as_deref(), state.as_deref()),
                            ))
                        })?;
                        match result {
                            Ok(page) => delivery_list_result(
                                deployment,
                                &options,
                                &page.items,
                                page.next_cursor.as_deref(),
                            ),
                            Err(failure) => failure_result(deployment, &options, failure),
                        }
                    })
                }
                Some(DeliveryLeaf::Show(cmd)) => {
                    let (webhook, delivery) = (cmd.webhook, cmd.delivery);
                    cmd.in_effect.execute(
                        cmd.options,
                        deployment,
                        |options, organization, project| {
                            let result = call(deployment, &options, |api| {
                                Ok(api.delivery(organization, project, &webhook, &delivery))
                            })?;
                            delivery_result(deployment, &options, result, "found", None)
                        },
                    )
                }
                Some(DeliveryLeaf::Replay(cmd)) => queued_delivery(
                    deployment,
                    (cmd.webhook, Some(cmd.delivery)),
                    cmd.in_effect,
                    cmd.options,
                    WebhookMutation::Replay,
                    "replayed",
                ),
                None => Err(anyhow!("delivery subcommand missing after help dispatch").into()),
            },
        }
    }
}
fn key() -> anyhow::Result<String> {
    useful_support::generate_idempotency_key().context("generate webhook request identity")
}
fn change(
    deployment: &Deployment,
    cmd: Target,
    mutation: WebhookMutation,
    outcome: &'static str,
) -> CommandResult {
    let webhook = cmd.webhook;
    cmd.in_effect
        .execute(cmd.options, deployment, |options, organization, project| {
            let key = key()?;
            let result = call(deployment, &options, |api| {
                Ok(api.mutate::<WebhookSubscription>(
                    mutation,
                    organization,
                    project,
                    (Some(&webhook), None),
                    &key,
                    None::<&Value>,
                ))
            })?;
            let context = Some(MutationContext {
                key: &key,
                project,
                webhook: Some(&webhook),
                delivery: None,
            });
            if matches!(mutation, WebhookMutation::Delete) {
                return match result {
                    Ok(None) => write_value(
                        deployment,
                        &options,
                        outcome,
                        "webhook",
                        &serde_json::json!({"id":webhook}),
                        format!("Webhook {webhook} deleted."),
                    ),
                    Ok(Some(_)) => failure_result_with_context(
                        deployment,
                        &options,
                        WebhookFailure::Protocol {
                            credential_rejected: false,
                        },
                        context,
                    ),
                    Err(failure) => {
                        failure_result_with_context(deployment, &options, failure, context)
                    }
                };
            }
            subscription_result(
                deployment,
                &options,
                result,
                outcome,
                matches!(mutation, WebhookMutation::Rotate),
                (Some(&webhook), project),
                context,
            )
        })
}
/// Queues a test delivery of the webhook, or a replay of its delivery.
fn queued_delivery(
    deployment: &Deployment,
    (webhook, delivery): (String, Option<String>),
    in_effect: InEffect,
    options: Options,
    mutation: WebhookMutation,
    outcome: &'static str,
) -> CommandResult {
    in_effect.execute(options, deployment, |options, organization, project| {
        let delivery = delivery.as_deref();
        let key = key()?;
        let result = call(deployment, &options, |api| {
            Ok(api.queue_delivery(mutation, organization, project, &webhook, delivery, &key))
        })?;
        delivery_result(
            deployment,
            &options,
            result,
            outcome,
            Some(MutationContext {
                key: &key,
                project,
                webhook: Some(&webhook),
                delivery,
            }),
        )
    })
}
fn call<T>(
    deployment: &Deployment,
    options: &Options,
    mut operation: impl FnMut(&WebhookApi) -> anyhow::Result<Result<T, WebhookFailure>>,
) -> anyhow::Result<Result<T, WebhookFailure>> {
    let policy = options.http.transport_policy();
    let client = HttpClient::new(policy)
        .map_err(|error| anyhow!(error))
        .context("prepare human session networking")?;
    super::super::execute_selected_api_operation(
        super::super::principal_api_context(
            &client,
            deployment,
            &options.authentication,
            "acquire human session for webhook operation",
        ),
        |token| {
            let api = WebhookApi::new(deployment.fingerprint().api_url(), token, policy)
                .map_err(|error| anyhow!(error))
                .context("prepare webhook networking")?;
            operation(&api)
        },
        WebhookFailure::credential_rejected,
        || WebhookFailure::Unauthenticated,
        WebhookFailure::Unreachable,
    )
}
fn subscription_result(
    deployment: &Deployment,
    options: &Options,
    result: Result<Option<WebhookSubscription>, WebhookFailure>,
    outcome: &'static str,
    reveal: bool,
    identity: (Option<&str>, &str),
    context: Option<MutationContext<'_>>,
) -> anyhow::Result<ExitCode> {
    let (expected, project) = identity;
    match result {
        Ok(Some(mut value)) => {
            if !reveal && value.secret.is_some() {
                return failure_result_with_context(
                    deployment,
                    options,
                    WebhookFailure::Protocol {
                        credential_rejected: false,
                    },
                    context,
                );
            }
            if expected.is_some_and(|id| id != value.id)
                || value.project_id != project
                || !useful_support::valid_typed_id(&value.id, "whs_")
                || value.version < 1
            {
                return failure_result_with_context(
                    deployment,
                    options,
                    WebhookFailure::Protocol {
                        credential_rejected: false,
                    },
                    context,
                );
            }
            if value
                .secret
                .as_ref()
                .is_some_and(|secret| !valid_secret(secret))
            {
                return failure_result_with_context(
                    deployment,
                    options,
                    WebhookFailure::Protocol {
                        credential_rejected: false,
                    },
                    context,
                );
            }
            if !reveal {
                value.secret = None;
            }
            let message = format!(
                "✓ Webhook {outcome}.\n\n{}{}",
                subscription_human(&value)?,
                if reveal && value.secret.is_none() {
                    "\nNo secret recovered; retain the original secret."
                } else {
                    ""
                },
            );
            write_value(
                deployment,
                options,
                outcome,
                "webhook",
                &value,
                if let Some(secret) = &value.secret {
                    format!("{message}\nSigning secret (shown once): {secret}")
                } else {
                    message
                },
            )
        }
        Ok(None) => failure_result_with_context(
            deployment,
            options,
            WebhookFailure::Protocol {
                credential_rejected: false,
            },
            context,
        ),
        Err(failure) => failure_result_with_context(deployment, options, failure, context),
    }
}
fn delivery_result(
    deployment: &Deployment,
    options: &Options,
    result: Result<WebhookDelivery, WebhookFailure>,
    outcome: &'static str,
    context: Option<MutationContext<'_>>,
) -> anyhow::Result<ExitCode> {
    match result {
        Ok(value) => write_value(
            deployment,
            options,
            outcome,
            "delivery",
            &value,
            format!(
                "✓ Delivery {outcome}.\n\n{}{}",
                delivery_human(&value, true)?,
                if outcome == "replayed" {
                    "\nMetadata only; no signing secret recovered."
                } else {
                    ""
                }
            ),
        ),
        Err(failure) => failure_result_with_context(deployment, options, failure, context),
    }
}
fn subscription_list_result(
    deployment: &Deployment,
    options: &Options,
    items: &[WebhookSubscription],
    cursor: Option<&str>,
) -> anyhow::Result<ExitCode> {
    if options.json {
        super::super::write_cloud_list_json(deployment.fingerprint().api_url(), items, cursor)?;
    } else {
        println!("✓ Webhooks listed.\n");
        for item in items {
            println!("{}\n", subscription_human(item)?);
        }
        list_footer(deployment, cursor);
    }
    Ok(ExitCode::Success)
}
fn delivery_list_result(
    deployment: &Deployment,
    options: &Options,
    items: &[WebhookDelivery],
    cursor: Option<&str>,
) -> anyhow::Result<ExitCode> {
    if options.json {
        super::super::write_cloud_list_json(deployment.fingerprint().api_url(), items, cursor)?;
    } else {
        println!("✓ Deliveries listed.\n");
        for item in items {
            println!("{}\n", delivery_human(item, false)?);
        }
        list_footer(deployment, cursor);
    }
    Ok(ExitCode::Success)
}
fn list_footer(deployment: &Deployment, cursor: Option<&str>) {
    if let Some(cursor) = cursor {
        println!("next cursor: {cursor}");
    }
    println!("deployment: {}", deployment.fingerprint().api_url());
}
fn subscription_human(value: &WebhookSubscription) -> anyhow::Result<String> {
    let mut text = format!(
        "webhook: {}\nproject: {}\nstate: {}\nversion: {}\nurl: {}\nevent types: {}\nworkflow paths: {}\ncontext keys: {}",
        value.id,
        value.project_id,
        enum_text(&value.state)?,
        value.version,
        value.url,
        value.event_types.join(", "),
        value
            .workflow_paths
            .as_ref()
            .map_or("all".to_owned(), |paths| paths.join(", ")),
        if value.context_keys.is_empty() {
            "none".to_owned()
        } else {
            value.context_keys.join(", ")
        }
    );
    if let Some(steps) = &value.steps {
        for step in steps {
            text.push_str(&format!(
                "\nstep: scope=[{}] · role={} · id={}",
                step.scope.join("/"),
                enum_text(&step.role)?,
                step.id
            ));
        }
    }
    if let Some(expiry) = &value.previous_key_expires_at {
        text.push_str(&format!("\nprevious key expires: {expiry}"));
    }
    text.push_str(&format!(
        "\ncreated: {}\nupdated: {}",
        value.created_at, value.updated_at
    ));
    Ok(text)
}
fn delivery_human(value: &WebhookDelivery, detail: bool) -> anyhow::Result<String> {
    let mut text = format!(
        "delivery: {}\nevent: {} ({})\nstate: {}\nrun: {}\nsubscription version: {}\ncreated: {}",
        value.id,
        value.event_id,
        value.event_type,
        enum_text(&value.state)?,
        value.run_id.as_deref().unwrap_or("none"),
        value.subscription_version,
        value.created_at
    );
    if let Some(sequence) = value.sequence {
        text.push_str(&format!("\nsequence: {sequence}"));
    }
    if let Some(path) = &value.workflow_path {
        text.push_str(&format!("\nworkflow path: {path}"));
    }
    if detail && let Some(cycles) = &value.cycles {
        for cycle in cycles {
            text.push_str(&format!(
                "\ncycle {}: {} · origin: {} · due: {}",
                cycle.number,
                enum_text(&cycle.state)?,
                enum_text(&cycle.origin)?,
                cycle.due_at
            ));
            if let Some(code) = &cycle.failure_code {
                text.push_str(&format!(" · failure: {}", enum_text(code)?));
            }
            for attempt in &cycle.attempts {
                text.push_str(&format!(
                    "\n  attempt: {} · started: {} · key version: {}",
                    attempt.id, attempt.started_at, attempt.current_key_version
                ));
                if let Some(status) = attempt.http_status {
                    text.push_str(&format!(" · HTTP: {status}"));
                }
                if let Some(code) = &attempt.failure_code {
                    text.push_str(&format!(" · failure: {}", enum_text(code)?));
                }
            }
        }
    }
    Ok(text)
}
fn enum_text(value: &impl serde::Serialize) -> anyhow::Result<String> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("invalid webhook field"))
}
fn write_value(
    deployment: &Deployment,
    options: &Options,
    outcome: &str,
    resource: &str,
    value: &impl serde::Serialize,
    human: String,
) -> anyhow::Result<ExitCode> {
    if options.json {
        let mut document = serde_json::json!({"schemaVersion": 1, "deployment": deployment.fingerprint().api_url(), "outcome": outcome});
        document[resource] = serde_json::to_value(value)?;
        if resource == "webhook" && matches!(outcome, "created" | "rotated") {
            document["secretDisclosure"] = serde_json::Value::String(
                if document[resource]["secret"].is_string() {
                    "shown_once"
                } else {
                    "metadata_only"
                }
                .to_owned(),
            );
        }
        if outcome == "replayed" {
            document["metadataOnly"] = serde_json::Value::Bool(true);
        }
        super::super::write_pretty_json(&document)?;
    } else {
        println!(
            "{human}\ndeployment: {}",
            deployment.fingerprint().api_url()
        );
    }
    Ok(ExitCode::Success)
}
#[derive(Clone, Copy)]
struct MutationContext<'a> {
    key: &'a str,
    project: &'a str,
    webhook: Option<&'a str>,
    delivery: Option<&'a str>,
}

fn failure_result(
    deployment: &Deployment,
    options: &Options,
    failure: WebhookFailure,
) -> anyhow::Result<ExitCode> {
    failure_result_with_context(deployment, options, failure, None)
}
fn failure_result_with_context(
    deployment: &Deployment,
    options: &Options,
    failure: WebhookFailure,
    context: Option<MutationContext<'_>>,
) -> anyhow::Result<ExitCode> {
    let (outcome, class, remedy, category, retry) = match failure {
        WebhookFailure::Unauthenticated => (
            "unauthenticated",
            OutcomeClass::Unauthenticated,
            "Sign in or check the service API key.",
            None,
            None,
        ),
        WebhookFailure::Forbidden => (
            "forbidden",
            OutcomeClass::Forbidden,
            "Ask an organization owner to perform this operation.",
            None,
            None,
        ),
        WebhookFailure::NotFound => (
            "not_found",
            OutcomeClass::GeneralFailure,
            "Check the organization and resource IDs.",
            None,
            None,
        ),
        WebhookFailure::InvalidInput => (
            "invalid_input",
            OutcomeClass::GeneralFailure,
            "Check the webhook configuration and try again.",
            None,
            None,
        ),
        WebhookFailure::Conflict => (
            "conflict",
            OutcomeClass::GeneralFailure,
            "Inspect the current subscription and retry with its version if appropriate.",
            None,
            None,
        ),
        WebhookFailure::ProjectArchived => (
            "project_archived",
            OutcomeClass::GeneralFailure,
            super::ARCHIVED_REMEDY,
            None,
            None,
        ),
        WebhookFailure::RateLimited(delay) => (
            "rate_limited",
            OutcomeClass::RateLimited,
            "Wait for the indicated interval before trying again.",
            None,
            Some(delay),
        ),
        WebhookFailure::Unreachable(category) => (
            "unreachable",
            super::super::unreachable_outcome_class(category),
            "The result may be uncertain. Inspect the subscription or delivery before starting a new mutation.",
            Some(category.as_str()),
            None,
        ),
        WebhookFailure::Protocol { .. } => (
            "invalid_response",
            OutcomeClass::Protocol,
            "The result may be uncertain. Inspect the subscription or delivery before trying again.",
            None,
            None,
        ),
    };
    if let Some(context) = context.filter(|_| {
        matches!(
            failure,
            WebhookFailure::Unreachable(_) | WebhookFailure::Protocol { .. }
        )
    }) {
        if options.json {
            let mut document = serde_json::json!({"schemaVersion": 1, "deployment": deployment.fingerprint().api_url(), "outcome": outcome,
                "idempotencyKey": context.key, "projectId": context.project, "nextAction": "inspect_resource"});
            if let Some(webhook) = context.webhook {
                document["webhookId"] = Value::String(webhook.to_owned());
            }
            if let Some(delivery) = context.delivery {
                document["deliveryId"] = Value::String(delivery.to_owned());
            }
            if let Some(category) = category {
                document["category"] = Value::String(category.to_owned());
            }
            super::super::write_pretty_json(&document)?;
        } else {
            use std::io::Write as _;
            writeln!(
                io::stderr().lock(),
                "error: webhook {outcome}\n\n{remedy}\nproject: {}\nwebhook: {}\ndelivery: {}\nidempotency key: {}",
                context.project,
                context.webhook.unwrap_or("unknown"),
                context.delivery.unwrap_or("unknown"),
                context.key
            )?;
        }
        return Ok(class.exit_code());
    }
    super::super::write_api_failure(
        deployment.fingerprint().api_url(),
        outcome,
        category,
        retry,
        &format!("error: webhook {outcome}\n\n{remedy}"),
        class,
        options.json,
    )
}

fn input_failure(
    deployment: &Deployment,
    options: &Options,
    error: &anyhow::Error,
) -> anyhow::Result<ExitCode> {
    super::super::write_api_failure(
        deployment.fingerprint().api_url(),
        "invalid_input",
        None,
        None,
        &format!("{error}\n\nCheck the webhook config and try again."),
        OutcomeClass::GeneralFailure,
        options.json,
    )
}

// Decode strictly before session acquisition; a 64-KiB cap also bounds standard input.
fn acquire(path: &Path, patch: bool, credential_stdin: bool) -> anyhow::Result<Map<String, Value>> {
    if path == Path::new("-") && credential_stdin {
        return Err(anyhow!(
            "error: standard input is already used by the service API key\n\nUse a regular config file instead."
        ));
    }
    let mut source: Box<dyn Read> = if path == Path::new("-") {
        Box::new(io::stdin())
    } else {
        Box::new(super::super::open_regular_file_nonblocking(path).map_err(|_| anyhow!("error: config file must be a readable regular file\n\nChoose a regular JSON file."))?)
    };
    let mut bytes = Vec::new();
    source
        .by_ref()
        .take(65_537)
        .read_to_end(&mut bytes)
        .context("read webhook config")?;
    if bytes.len() > 65_536 {
        return Err(anyhow!(
            "error: webhook config exceeds 64 KiB\n\nUse a smaller config."
        ));
    }
    let value = useful_support::strict_json_from_slice(&bytes).map_err(|_| {
        anyhow!("error: config is not strict JSON\n\nRemove duplicate members and check syntax.")
    })?;
    let map = value.as_object().ok_or_else(|| {
        anyhow!("error: config must be a JSON object\n\nSupply selection members.")
    })?;
    let allowed = if patch {
        &["eventTypes", "workflowPaths", "steps", "contextKeys"][..]
    } else {
        &["url", "eventTypes", "workflowPaths", "steps", "contextKeys"][..]
    };
    if map.keys().any(|key| !allowed.contains(&key.as_str()))
        || map.is_empty()
        || (!patch && (!map.contains_key("url") || !map.contains_key("eventTypes")))
    {
        return Err(anyhow!(
            "error: unknown or missing config member\n\nUse the documented webhook selection fields."
        ));
    }
    if let Some(url) = map.get("url") {
        let url = url
            .as_str()
            .ok_or_else(|| anyhow!("error: invalid webhook URL"))?;
        let parsed = url::Url::parse(url).map_err(|_| anyhow!("error: invalid webhook URL"))?;
        let authority = url
            .split_once("://")
            .and_then(|(scheme, rest)| scheme.eq_ignore_ascii_case("https").then_some(rest))
            .and_then(|rest| rest.split('/').next());
        if url.len() > 2048
            || authority.is_none_or(|host| host.contains('@'))
            || url.as_bytes().iter().any(u8::is_ascii_control)
            || url.chars().next().is_some_and(char::is_whitespace)
            || url.contains(['?', '#'])
            || parsed.scheme() != "https"
            || !matches!(parsed.host(), Some(url::Host::Domain(host)) if !host.ends_with('.'))
            || parsed.port().is_some_and(|port| port != 443)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(anyhow!(
                "error: invalid webhook URL\n\nUse a public HTTPS hostname on port 443 without query or fragment."
            ));
        }
    }
    for (field, maximum, nonempty) in [
        ("eventTypes", 14, true),
        ("workflowPaths", 64, true),
        ("steps", 64, true),
        ("contextKeys", 32, false),
    ] {
        let Some(value) = map.get(field) else {
            continue;
        };
        let entries = value
            .as_array()
            .ok_or_else(|| anyhow!("error: {field} must be an array"))?;
        if entries.len() > maximum || nonempty && entries.is_empty() {
            return Err(anyhow!("error: invalid {field} selection"));
        }
        let mut unique = HashSet::new();
        for entry in entries {
            match field {
                "steps" => {
                    let step = entry
                        .as_object()
                        .ok_or_else(|| anyhow!("error: invalid step selector"))?;
                    if step.len() != 3
                        || !["scope", "role", "id"]
                            .iter()
                            .all(|key| step.contains_key(*key))
                        || !["step", "finalizer"].contains(&step["role"].as_str().unwrap_or(""))
                        || !short(step["id"].as_str())
                    {
                        return Err(anyhow!("error: invalid step selector"));
                    }
                    let scope = step["scope"]
                        .as_array()
                        .ok_or_else(|| anyhow!("error: invalid step scope"))?;
                    if scope.len() > 64 || !scope.iter().all(|v| short(v.as_str())) {
                        return Err(anyhow!("error: invalid step scope"));
                    }
                }
                "eventTypes" => {
                    if ![
                        "run.queued",
                        "run.started",
                        "run.succeeded",
                        "run.failed",
                        "run.cancelled",
                        "run.interrupted",
                        "run.rejected",
                        "step.started",
                        "step.succeeded",
                        "step.failed",
                        "step.skipped",
                        "step.cancelled",
                        "step.blocked",
                        "step.not_run",
                        "publication.published",
                        "publication.no_changes",
                        "publication.already_merged",
                        "publication.failed",
                        "publication.unavailable",
                    ]
                    .contains(&entry.as_str().unwrap_or(""))
                    {
                        return Err(anyhow!("error: invalid event type"));
                    }
                }
                "workflowPaths" => {
                    let path = entry
                        .as_str()
                        .ok_or_else(|| anyhow!("error: invalid workflow path"))?;
                    if path.starts_with('/')
                        || path.ends_with('/')
                        || path.split('/').any(|part| {
                            part.is_empty() || part == "." || part == ".." || part.contains('\0')
                        })
                    {
                        return Err(anyhow!("error: invalid workflow path"));
                    }
                }
                _ => {
                    if !short(entry.as_str()) {
                        return Err(anyhow!("error: invalid context key"));
                    }
                }
            }
            if !unique.insert(entry.to_string()) {
                return Err(anyhow!("error: duplicate {field} selection"));
            }
        }
    }
    // Generated wire models remain the type boundary; the strict input map is retained
    // for deterministic bytes and exact omitted-versus-empty collection semantics.
    if patch {
        let mut document = map.clone();
        document.insert("expectedVersion".to_owned(), Value::from(1));
        let _: useful_api::PatchWebhookSubscriptionRequest =
            serde_json::from_value(Value::Object(document))
                .map_err(|_| anyhow!("error: invalid webhook selection"))?;
    } else {
        let _: useful_api::CreateWebhookSubscriptionRequest = serde_json::from_value(value.clone())
            .map_err(|_| anyhow!("error: invalid webhook selection"))?;
    }
    Ok(map.clone())
}
fn valid_secret(encoded: &str) -> bool {
    let Ok(bytes) = STANDARD.decode(encoded).map(Zeroizing::new) else {
        return false;
    };
    bytes.len() == 32 && STANDARD.encode(bytes.as_slice()) == encoded
}

fn short(value: Option<&str>) -> bool {
    value.is_some_and(|s| !s.is_empty() && s.len() <= 64)
}
