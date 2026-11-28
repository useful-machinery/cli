//! What the tree of an assignment admitted in `cloud` mode calls for, and whether the runner
//! holds it. The tree calls for the kinds the doctor derives
//! over its root and the files the root's `workflow` steps name, a forwarded variable's kind
//! only where the assignment blocks the name, and the provider of each row of Cloud's
//! provider table one of whose blocked names a covered file forwards; a root that declares
//! its integrations is not checked. A provider is held where the admission's offer carries
//! its credential, read from what the offer settled; one it does not hold is
//! missing only where Cloud answered this admission's request and the answer leaves the
//! runner none, and anything else is unsettled. One function, `decide`, settles it, and
//! `CredentialCheck::check` turns its verdict into the assignment's decline.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use useful_runner_protocol::{
    AssignmentDecline, DeclineProviders, ExecutionSpecInvalidReason, RunnerUnableReason,
};

use super::Offer;
use super::blocked::{AdmittedMode, BlockedNames};
use super::cloud::{ListedProvider, TokenServiceSource};
use super::grant_token::AssignmentGrantTokens;
use super::setup::SetupOutcome;
use crate::control_protocol::{AgentLoginProvider, AgentLoginState, CredentialSource};
use crate::doctor::{CredentialKind, DerivedCredentials, OriginDeclaration, RepositorySource};

/// The stage each decline of the check names.
const STAGE: &str = "credential_check";

/// What an admission's request for a provider left the runner, where it holds nothing of it.
/// The variants are declared from the surest that nothing is held to the least, so that of
/// two answers for one provider the greater stands.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Answer {
    /// Cloud answered, and the answer leaves the runner none.
    Refused,
    /// Cloud answered, but the runner could not keep what it issued, or another run kept
    /// the setup from asking or finishing.
    Unsettled,
    /// The request got no usable answer from Cloud.
    Unanswered,
}

impl Answer {
    /// A token request's outcome, by the state the admission settled it in.
    const fn of_token(state: AgentLoginState) -> Self {
        match state {
            AgentLoginState::NotAuthorized
            | AgentLoginState::Revoked
            | AgentLoginState::ReconnectRequired
            | AgentLoginState::UnsupportedTarget => Self::Refused,
            AgentLoginState::CloudUnavailable => Self::Unanswered,
            AgentLoginState::Ready
            | AgentLoginState::ForeignLogin
            | AgentLoginState::StaleGeneration
            | AgentLoginState::InstallFailed
            | AgentLoginState::NotDelivered => Self::Unsettled,
        }
    }

    /// A coding agent's state as the admission's pass recorded it from Cloud's answer to its
    /// status request.
    const fn of_login(state: AgentLoginState) -> Self {
        match state {
            AgentLoginState::NotAuthorized
            | AgentLoginState::Revoked
            | AgentLoginState::UnsupportedTarget => Self::Refused,
            AgentLoginState::CloudUnavailable => Self::Unanswered,
            AgentLoginState::Ready
            | AgentLoginState::ForeignLogin
            | AgentLoginState::StaleGeneration
            | AgentLoginState::InstallFailed
            | AgentLoginState::NotDelivered
            | AgentLoginState::ReconnectRequired => Self::Unsettled,
        }
    }
}

/// What Cloud answered the requests of one admission, as its hold keeps them: whether it
/// answered both the list of the assignment's providers and that of its token services, and
/// what each token request and the admission's agent-login pass settled, by provider id.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Answers {
    lists_answered: bool,
    providers: BTreeMap<String, Answer>,
}

impl Answers {
    /// The answers of an admission whose token requests settled each provider id in its
    /// state, `settled`, and that Cloud answered both lists for where `lists_answered`.
    pub(crate) fn of_requests<'a>(
        settled: impl IntoIterator<Item = (&'a str, AgentLoginState)>,
        lists_answered: bool,
    ) -> Self {
        let mut answers = Self {
            lists_answered,
            providers: BTreeMap::new(),
        };
        for (id, state) in settled {
            answers.note(id, Answer::of_token(state));
        }
        answers
    }

    /// Notes each coding agent as the admission's pass left it: the state the pass recorded
    /// where it ran to the end and Cloud answered its status request (`answered`), Cloud's
    /// silence where it did not, and unsettled where no pass was made, it failed or the gate
    /// stopped it.
    pub(crate) fn note_agent_logins(&mut self, pass: Option<(&SetupOutcome, bool)>) {
        for provider in AgentLoginProvider::INSTALLABLE {
            let answer = match pass {
                Some((SetupOutcome::Recorded(document), true)) => document
                    .login(provider)
                    .map_or(Answer::Unsettled, |login| Answer::of_login(login.state)),
                Some((SetupOutcome::Recorded(_), false)) => Answer::Unanswered,
                Some((SetupOutcome::Busy(_) | SetupOutcome::Failed, _)) | None => Answer::Unsettled,
            };
            self.note(provider_id(provider), answer);
        }
    }

    /// Notes `answer` for `id`; of two answers for one provider the less sure stands.
    fn note(&mut self, id: &str, answer: Answer) {
        let noted = self.providers.entry(id.to_owned()).or_insert(answer);
        *noted = (*noted).max(answer);
    }

    /// What the admission's requests leave of `id`, which the runner does not hold: what its
    /// request answered or, for a provider no request was made for, missing where Cloud
    /// answered both lists and neither names it, and unanswered otherwise.
    pub(crate) fn of(&self, id: &str) -> Answer {
        match self.providers.get(id) {
            Some(answer) => *answer,
            None if self.lists_answered => Answer::Refused,
            None => Answer::Unanswered,
        }
    }
}

/// A provider's id as Cloud names it: `gitlab.com` for GitLab, a coding agent's own name.
fn provider_id(provider: AgentLoginProvider) -> &'static str {
    provider.grant_provider().unwrap_or(provider.as_str())
}

/// What `decide` settles for a tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Verdict {
    /// The runner holds every provider the tree calls for, or the tree is not checked.
    Holds,
    /// Cloud's answers leave the runner none of these, in order: the doctor's kinds in its
    /// order, then every other id bytewise.
    Missing(Vec<String>),
    /// None is missing, and Cloud gave no usable answer for one the runner lacks.
    Unanswered,
    /// None is missing, and the runner lacks one for any other reason.
    Unsettled,
}

/// A provider the tree calls for, ordered as a decline names it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Called {
    Kind(CredentialKind),
    Other(String),
}

impl Called {
    fn of(id: &str) -> Self {
        CredentialKind::ALL
            .into_iter()
            .find(|kind| kind.provider_id() == id)
            .map_or_else(|| Self::Other(id.to_owned()), Self::Kind)
    }

    fn id(&self) -> &str {
        match self {
            Self::Kind(kind) => kind.provider_id(),
            Self::Other(id) => id,
        }
    }
}

/// Whether the runner, holding `held` and answered `answers`, lacks a provider the tree of
/// `derived` and `forwarded` calls for, an assignment that blocks `blocked` and was listed
/// the provider table's `rows`. A root that declares its integrations is not checked
/// (`differences` is present). A kind is called for by any origin but a forwarded variable,
/// and by a forwarded variable only where `blocked` holds its name; a forwarded name that
/// `blocked` holds and is one of a row's two names calls for that row's provider. Any missing
/// provider is `Missing`, naming every missing one; with none missing, a provider Cloud gave
/// no usable answer for is `Unanswered`, and any other the runner lacks `Unsettled`.
pub(crate) fn decide(
    derived: &DerivedCredentials,
    forwarded: &BTreeSet<String>,
    blocked: &BlockedNames,
    rows: &[ListedProvider],
    held: &BTreeSet<String>,
    answers: &Answers,
) -> Verdict {
    if derived.differences.is_some() {
        return Verdict::Holds;
    }
    let mut called = BTreeSet::new();
    for requirement in &derived.inferred.requirements {
        let calls = requirement.origins.iter().any(|origin| {
            origin.declaration != OriginDeclaration::ForwardedVariable
                || origin
                    .name
                    .as_deref()
                    .is_some_and(|name| blocked.blocks(name))
        });
        if calls {
            called.insert(Called::Kind(requirement.kind));
        }
    }
    for name in forwarded.iter().filter(|name| blocked.blocks(name)) {
        for row in rows
            .iter()
            .filter(|row| row.token == *name || row.token_file == *name)
        {
            called.insert(Called::of(&row.provider));
        }
    }
    let mut missing = Vec::new();
    let mut lacking = None;
    for id in called
        .iter()
        .map(Called::id)
        .filter(|id| !held.contains(*id))
    {
        match answers.of(id) {
            Answer::Refused => missing.push(id.to_owned()),
            answer => lacking = lacking.max(Some(answer)),
        }
    }
    if !missing.is_empty() {
        return Verdict::Missing(missing);
    }
    match lacking {
        None | Some(Answer::Refused) => Verdict::Holds,
        Some(Answer::Unsettled) => Verdict::Unsettled,
        Some(Answer::Unanswered) => Verdict::Unanswered,
    }
}

/// The inputs of the check of one assignment admitted in `cloud` mode, settled by its
/// admission from its offer and its hold before the tree is on disk.
#[derive(Debug)]
pub(crate) struct CredentialCheck {
    blocked: BlockedNames,
    rows: Vec<ListedProvider>,
    held: BTreeSet<String>,
    answers: Answers,
}

impl CredentialCheck {
    /// The check of the admission whose offer is `offer` and whose hold is `grant_tokens`;
    /// none unless the offer was made in `cloud`. A provider is held where `offer` carries
    /// its credential: one of the five whose source it settled as `grant`, a token service
    /// whose source is `token`, and any other provider the hold kept a token of.
    pub(crate) fn of_admission(
        offer: &Offer,
        grant_tokens: Option<&AssignmentGrantTokens>,
    ) -> Option<Self> {
        let AdmittedMode::Cloud(blocked) = &offer.commands.mode else {
            return None;
        };
        let held = offer
            .sources
            .iter()
            .filter(|source| {
                matches!(
                    source.source,
                    CredentialSource::Grant | CredentialSource::OrgConnection
                )
            })
            .map(|source| provider_id(source.provider).to_owned())
            .chain(
                offer
                    .token_services
                    .iter()
                    .filter(|service| matches!(service.source, TokenServiceSource::Token { .. }))
                    .map(|service| service.provider.clone()),
            )
            .chain(
                grant_tokens
                    .into_iter()
                    .flat_map(AssignmentGrantTokens::kept_configured)
                    .map(str::to_owned),
            )
            .collect();
        Some(Self {
            blocked: blocked.clone(),
            rows: grant_tokens
                .and_then(AssignmentGrantTokens::credential_providers)
                .and_then(|answer| answer.as_ref().ok())
                .cloned()
                .unwrap_or_default(),
            held,
            answers: grant_tokens
                .map(|tokens| tokens.answers().clone())
                .unwrap_or_default(),
        })
    }

    /// Checks the tree at `tree`, whose root is `workflow_path`, reading it as the doctor
    /// does with no repository: `grant_required` naming the missing providers, `runner_unable`
    /// `input_service_unavailable` where the runner lacks one and none is missing, and
    /// `workflow_source_invalid` where the tree cannot be read. It reads small files, on the
    /// admission's blocking worker.
    pub(crate) fn check(&self, tree: &Path, workflow_path: &str) -> Result<(), AssignmentDecline> {
        let (derived, forwarded) = DerivedCredentials::read_with_forwarded_names(
            tree,
            &[tree.join(workflow_path)],
            RepositorySource::Project(None),
        )
        .map_err(|_| {
            AssignmentDecline::ExecutionSpecInvalid(
                ExecutionSpecInvalidReason::WorkflowSourceInvalid,
            )
            .diagnosed(STAGE, "workflow_tree_unreadable")
        })?;
        match decide(
            &derived,
            &forwarded,
            &self.blocked,
            &self.rows,
            &self.held,
            &self.answers,
        ) {
            Verdict::Holds => Ok(()),
            Verdict::Missing(ids) => Err(AssignmentDecline::ExecutionSpecInvalid(
                ExecutionSpecInvalidReason::GrantRequired,
            )
            .diagnosed(STAGE, "grant_missing")
            .with_providers(DeclineProviders::new(ids))),
            Verdict::Unanswered => Err(unable("cloud_unanswered")),
            Verdict::Unsettled => Err(unable("credential_unsettled")),
        }
    }
}

/// The decline of an assignment the runner lacks a provider for, none missing, which Cloud
/// offers again.
fn unable(cause: &'static str) -> AssignmentDecline {
    AssignmentDecline::RunnerUnable(RunnerUnableReason::InputServiceUnavailable)
        .diagnosed(STAGE, cause)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{Answer, Answers, Verdict, decide};
    use crate::agent_login::blocked::BlockedNames;
    use crate::agent_login::cloud::ListedProvider;
    use crate::control_protocol::AgentLoginState;
    use crate::doctor::{
        CredentialKind, CredentialRequirement, Declaration, DerivedCredentials, OriginDeclaration,
        ReadinessCode, WorkflowCredentials,
    };

    /// A requirement of `kind` called for by each of `origins`, a declaration with its name.
    fn requirement(
        kind: CredentialKind,
        origins: &[(OriginDeclaration, &str)],
    ) -> CredentialRequirement {
        CredentialRequirement {
            kind,
            code: ReadinessCode::NotChecked,
            origins: origins
                .iter()
                .map(|(declaration, name)| Declaration {
                    workflow: Some("workflow.yaml".to_owned()),
                    declaration: *declaration,
                    node: None,
                    name: Some((*name).to_owned()),
                })
                .collect(),
        }
    }

    /// The derivation of a root inferring `requirements`, which declares its integrations
    /// where `declares`.
    fn derived(requirements: Vec<CredentialRequirement>, declares: bool) -> DerivedCredentials {
        let credentials = WorkflowCredentials {
            workflows: vec!["workflow.yaml".to_owned()],
            requirements,
            unknown: Vec::new(),
        };
        DerivedCredentials {
            inferred: credentials.clone(),
            reported: credentials,
            differences: declares.then(Vec::new),
            slack: Vec::new(),
        }
    }

    fn row(provider: &str, token: &str, token_file: &str) -> ListedProvider {
        ListedProvider {
            provider: provider.to_owned(),
            token: token.to_owned(),
            token_file: token_file.to_owned(),
        }
    }

    fn ids(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|id| (*id).to_owned()).collect()
    }

    fn answered(answers: &[(&str, Answer)], lists_answered: bool) -> Answers {
        let mut noted = Answers::of_requests([], lists_answered);
        for (id, answer) in answers {
            noted.note(id, *answer);
        }
        noted
    }

    /// One row of the decision's table: what it shows, the derivation, the names forwarded,
    /// the providers held, the answers and the verdict.
    type Case<'a> = (
        &'a str,
        DerivedCredentials,
        &'a [&'a str],
        &'a [&'a str],
        Answers,
        Verdict,
    );

    fn missing(ids: &[&str]) -> Verdict {
        Verdict::Missing(ids.iter().map(|id| (*id).to_owned()).collect())
    }

    // what a tree calls for, held, missing or unsettled, and the
    // order the missing ones are named in.
    #[test]
    fn the_decision_rests_on_what_the_offer_holds_and_what_cloud_answered() {
        use Answer::{Refused, Unanswered, Unsettled};
        use OriginDeclaration::{AgentProfile, Binding, ForwardedVariable};

        let linear = || requirement(CredentialKind::Linear, &[(Binding, "team")]);
        let github = || requirement(CredentialKind::Github, &[(Binding, "repository")]);
        let rows = [
            row(
                "linear",
                "USEFUL_LINEAR_ACCESS_TOKEN",
                "USEFUL_LINEAR_ACCESS_TOKEN_FILE",
            ),
            row(
                "umlinear",
                "UM_LINEAR_ACCESS_TOKEN",
                "UM_LINEAR_ACCESS_TOKEN_FILE",
            ),
            row("anthropic", "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY_FILE"),
            row("openai", "OPENAI_API_KEY", "OPENAI_API_KEY_FILE"),
        ];
        let cases: Vec<Case<'_>> = vec![
            (
                "held passes whatever was answered",
                derived(vec![linear()], false),
                &[],
                &["linear"],
                answered(&[("linear", Refused)], true),
                Verdict::Holds,
            ),
            (
                "a refusal is missing",
                derived(vec![linear()], false),
                &[],
                &[],
                answered(&[("linear", Refused)], false),
                missing(&["linear"]),
            ),
            (
                "a provider neither answered list names is missing",
                derived(vec![linear()], false),
                &[],
                &[],
                answered(&[], true),
                missing(&["linear"]),
            ),
            (
                "a list Cloud did not answer is unanswered",
                derived(vec![linear()], false),
                &[],
                &[],
                answered(&[], false),
                Verdict::Unanswered,
            ),
            (
                "an unanswered request alone is unanswered",
                derived(vec![linear()], false),
                &[],
                &[],
                answered(&[("linear", Unanswered)], true),
                Verdict::Unanswered,
            ),
            (
                "unsettled alone is unsettled",
                derived(vec![linear()], false),
                &[],
                &[],
                answered(&[("linear", Unsettled)], true),
                Verdict::Unsettled,
            ),
            (
                "an unanswered request outweighs an unsettled one",
                derived(vec![github(), linear()], false),
                &[],
                &[],
                answered(&[("github", Unsettled), ("linear", Unanswered)], true),
                Verdict::Unanswered,
            ),
            (
                "missing beside unsettled names the missing ones only",
                derived(vec![github(), linear()], false),
                &[],
                &[],
                answered(&[("github", Unanswered), ("linear", Refused)], true),
                missing(&["linear"]),
            ),
            (
                "the doctor's kinds in its order, then every other id bytewise",
                derived(
                    vec![
                        github(),
                        requirement(CredentialKind::ClaudeCode, &[(AgentProfile, "review")]),
                    ],
                    false,
                ),
                &[
                    "UM_LINEAR_ACCESS_TOKEN",
                    "ANTHROPIC_API_KEY",
                    "USEFUL_LINEAR_ACCESS_TOKEN",
                ],
                &[],
                answered(&[("claude_code", Refused)], true),
                missing(&["github", "linear", "claude_code", "anthropic", "umlinear"]),
            ),
            (
                "a forwarded name the assignment does not block calls for nothing",
                derived(
                    vec![requirement(
                        CredentialKind::Codex,
                        &[(ForwardedVariable, "OPENAI_API_KEY")],
                    )],
                    false,
                ),
                &["OPENAI_API_KEY"],
                &[],
                answered(&[], true),
                Verdict::Holds,
            ),
            (
                "a forwarded name the assignment blocks calls for its kind",
                derived(
                    vec![requirement(
                        CredentialKind::Github,
                        &[(ForwardedVariable, "GH_TOKEN")],
                    )],
                    false,
                ),
                &["GH_TOKEN"],
                &[],
                answered(&[], true),
                missing(&["github"]),
            ),
            (
                "a forwarded blocked name of a listed row calls for the row's id",
                derived(Vec::new(), false),
                &["ANTHROPIC_API_KEY"],
                &[],
                answered(&[], true),
                missing(&["anthropic"]),
            ),
            (
                "a root that declares its integrations is not checked",
                derived(vec![linear()], true),
                &["ANTHROPIC_API_KEY"],
                &[],
                answered(&[("linear", Refused)], true),
                Verdict::Holds,
            ),
        ];
        let blocked = BlockedNames::fixed();
        for (case, derived, forwarded, held, answers, verdict) in cases {
            assert_eq!(
                decide(
                    &derived,
                    &ids(forwarded),
                    &blocked,
                    &rows,
                    &ids(held),
                    &answers,
                ),
                verdict,
                "{case}"
            );
        }
    }

    // a token Cloud refused is missing, one it gave no usable
    // answer for is unanswered, and one the runner could not keep is unsettled; of two answers
    // for one provider the less sure stands.
    #[test]
    fn each_token_outcome_is_read_as_cloud_answered_it() {
        for (state, answer) in [
            (AgentLoginState::NotAuthorized, Answer::Refused),
            (AgentLoginState::Revoked, Answer::Refused),
            (AgentLoginState::ReconnectRequired, Answer::Refused),
            (AgentLoginState::UnsupportedTarget, Answer::Refused),
            (AgentLoginState::CloudUnavailable, Answer::Unanswered),
            (AgentLoginState::InstallFailed, Answer::Unsettled),
            (AgentLoginState::Ready, Answer::Unsettled),
        ] {
            assert_eq!(
                Answers::of_requests([("linear", state)], true).of("linear"),
                answer,
                "{state:?}"
            );
        }
        let both = Answers::of_requests(
            [
                ("mergify", AgentLoginState::NotAuthorized),
                ("mergify", AgentLoginState::CloudUnavailable),
            ],
            true,
        );
        assert_eq!(both.of("mergify"), Answer::Unanswered);
    }
}
