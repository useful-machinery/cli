//! The statement a leaf of `useful account integration` makes before it acts on a grant or a
//! token, and its `--yes`,
//! which refuses a missing confirmation with that statement, or, for `authorize` and
//! `deauthorize` on a terminal, is asked for in its place. The `[y/N]` question every grant
//! command asks on a terminal is here too.

use std::fmt;
use std::io::{self, BufRead, IsTerminal, Write};
use std::marker::PhantomData;

use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{ArgAction, ArgMatches, Args, CommandFactory, FromArgMatches};

use crate::exit_code::ExitCode;
use useful_api::MemberGrantKind;

/// Who can use a native grant once a runner holds it (REQ-GRANT-66).
pub(in crate::cli) const NATIVE_AUTHORIZE: &[&str] = &[
    "every run the runner serves can use the agent login, whichever member caused the run",
    "every step on the runner can read the agent login",
];

/// The stop Cloud requests of the runner's run when a native grant's authorization ends
/// (REQ-GRANT-48).
pub(in crate::cli) const NATIVE_DEAUTHORIZE: &[&str] =
    &["the run the runner is serving will be asked to stop, whichever member started it"];

/// The stop Cloud requests of each runner's run when a native grant is revoked (REQ-GRANT-48).
pub(in crate::cli) const NATIVE_REVOKE: &[&str] = &[
    "the run each of the agent login's runners is serving will be asked to stop, whichever \
     member started it",
];

/// What ending a runner's authorization for a token does, whoever's it is (REQ-INTEGRATION-20).
pub(in crate::cli) const TOKEN_DEAUTHORIZE: &[&str] = &[
    "the runner is issued the token no more; a running assignment loses it at its next refresh, \
     within five minutes",
];

/// What revoking a token does, whoever's it is (REQ-INTEGRATION-20).
pub(in crate::cli) const TOKEN_REVOKE: &[&str] =
    &["the token is erased from Cloud; it stays valid at the service until it is ended there"];

/// What a statement depends on: the kind of the grant a leaf acts on, or that it acts on the
/// member's or the organization's token of a token service (REQ-INTEGRATION-20), or on a
/// runner's authorization for one of the organization's connections in one project
/// (REQ-INTEGRATION-33).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::cli) enum Kind {
    Grant(MemberGrantKind),
    Token,
    OrgToken,
    Connection,
}

impl Kind {
    /// What the statement of several kinds calls a subject of this kind.
    const fn subject(self) -> &'static str {
        match self {
            Self::Grant(MemberGrantKind::GrantKindOAuth) => "an OAuth grant",
            Self::Grant(MemberGrantKind::GrantKindNative) => "a native grant",
            Self::Token => "your token",
            Self::OrgToken => "the organization's token",
            Self::Connection => "a connection",
        }
    }
}

/// What acting does, by the kind of what the leaf acts on, which it knows only once it has read
/// what the name names: the lines of each kind the leaf can act on, in the order a statement of
/// them all states them.
pub(in crate::cli) struct Statement(pub(in crate::cli) &'static [(Kind, &'static [&'static str])]);

impl Statement {
    /// The lines that state what acting on a subject of `kind` does.
    pub(in crate::cli) fn of(&self, kind: Kind) -> &'static [&'static str] {
        self.0
            .iter()
            .find_map(|(of, lines)| (*of == kind).then_some(*lines))
            .unwrap_or_default()
    }

    /// Every line, each attributed to its kind: a refusal made before anything is read, and
    /// `authorize --all`, which acts on every kind, state them all.
    pub(in crate::cli) fn every_line(&self) -> Vec<String> {
        self.0
            .iter()
            .flat_map(|(kind, lines)| {
                lines
                    .iter()
                    .map(move |line| format!("for {}, {line}", kind.subject()))
            })
            .collect()
    }
}

/// A leaf that states what acting does before it acts, and in place of acting when `--yes` is
/// missing where it cannot ask: `authorize` who can use the grant (REQ-GRANT-66), `revoke` and
/// `deauthorize` the runs that will be asked to stop (REQ-GRANT-67, REQ-GRANT-68).
pub(in crate::cli) trait Stated: Args {
    /// The leaf's command path, which the refusal's usage names.
    const COMMAND: &'static str;
    /// The statement.
    const STATEMENT: Statement;
    /// What the leaf does, as the refusal's remedy names it.
    const ACTION: &'static str;

    /// Whether a missing `--yes` is left to the leaf rather than refused before it runs, so that
    /// it can ask in its place (REQ-GRANT-82, [`asks`]): only `authorize` and `deauthorize` do.
    const ASKS: bool = false;
}

/// States `lines`, on standard error under `heading`: what a leaf is about to do.
pub(in crate::cli) fn state(
    heading: fmt::Arguments<'_>,
    lines: &[impl AsRef<str>],
) -> io::Result<()> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "{heading}")?;
    for line in lines {
        writeln!(stderr, "  {}", line.as_ref())?;
    }
    Ok(())
}

/// Whether a grant command can ask the member: standard input and standard error both are
/// terminals. Standard output may be piped, since it carries only the result.
pub(in crate::cli) fn can_ask() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

/// Asks `question` on standard error with `[y/N]` and reads one line of answer from standard
/// input: whether it is yes. The grant commands ask every question this way.
pub(super) fn ask(question: fmt::Arguments<'_>) -> io::Result<bool> {
    let mut stderr = io::stderr().lock();
    write!(stderr, "{question} [y/N] ")?;
    stderr.flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// After the statement of a leaf given its runner without `--yes` where it can ask
/// (REQ-GRANT-82, INV-CLI-16): asks whether to go on, the question `--yes` stands for. Any
/// answer but yes is reported, having sent nothing, and the leaf exits 2.
pub(in crate::cli) fn go_on(asks: bool) -> anyhow::Result<Result<(), ExitCode>> {
    if !asks || ask(format_args!("Continue?"))? {
        return Ok(Ok(()));
    }
    writeln!(io::stderr().lock(), "error: not confirmed, nothing sent")?;
    Ok(Err(ExitCode::UsageError))
}

/// The `--yes` of a `Stated` leaf `C`, required like `ConfirmationArgs`, whose absence is
/// refused with the leaf's statement: clap's own refusal of a missing required argument cannot
/// carry it. A leaf that asks in its place (`Stated::ASKS`) parses without it and checks it as
/// it runs ([`asks`]).
pub(in crate::cli) struct Confirmation<C> {
    /// Whether `--yes` was given: always, unless the leaf asks in its place.
    pub(in crate::cli) yes: bool,
    stated: PhantomData<fn() -> C>,
}

impl<C> fmt::Debug for Confirmation<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Confirmation")
            .field("yes", &self.yes)
            .finish()
    }
}

const YES: &str = "yes";

impl<C: Stated> Args for Confirmation<C> {
    fn augment_args(command: clap::Command) -> clap::Command {
        command.arg(
            clap::Arg::new(YES)
                .long(YES)
                .action(ArgAction::SetTrue)
                .help("Confirm this action"),
        )
    }

    fn augment_args_for_update(command: clap::Command) -> clap::Command {
        Self::augment_args(command)
    }
}

impl<C: Stated> FromArgMatches for Confirmation<C> {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        let yes = matches.get_flag(YES);
        if yes || C::ASKS {
            return Ok(Self {
                yes,
                stated: PhantomData,
            });
        }
        Err(missing_yes::<C>())
    }

    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}

/// Whether the leaf `C`, given its runner, asks before it acts (REQ-GRANT-82): not with
/// `--yes`; without it, where it can ask, `--json` absent, it asks after its statement
/// ([`go_on`]). Elsewhere it refuses, before anything is read or sent, as a missing `--yes` is
/// refused when the command line is parsed, and exits 2.
pub(in crate::cli) fn asks<C: Stated>(
    yes: bool,
    json: bool,
) -> anyhow::Result<Result<bool, ExitCode>> {
    if yes {
        return Ok(Ok(false));
    }
    if !json && can_ask() {
        return Ok(Ok(true));
    }
    missing_yes::<C>()
        .format(&mut super::super::super::Cli::command())
        .print()?;
    Ok(Err(ExitCode::UsageError))
}

/// The refusal of a missing `--yes` for the leaf `C`: what acting does for both kinds, since
/// it is made before the grant is read, and the remedy that names `--yes`.
fn missing_yes<C: Stated>() -> clap::Error {
    let mut error = usage_error::<C>(ErrorKind::MissingRequiredArgument);
    error.insert(
        ContextKind::InvalidArg,
        ContextValue::Strings(vec![format!("--{YES}")]),
    );
    let remedy = format!("{}, run the command again with --{YES}", C::ACTION);
    error.insert(
        ContextKind::Suggested,
        ContextValue::StyledStrs(
            C::STATEMENT
                .every_line()
                .into_iter()
                .chain([remedy])
                .map(Into::into)
                .collect(),
        ),
    );
    error
}

/// A usage error of kind `kind` with the usage of the leaf `C` at `C::COMMAND`, which the error's
/// context completes: an error a leaf raises as it reads its arguments is formatted with the
/// root command, whose usage is not the leaf's.
fn usage_error<C: Stated>(kind: ErrorKind) -> clap::Error {
    let mut error = clap::Error::new(kind);
    let name = C::COMMAND.rsplit(' ').next().unwrap_or(C::COMMAND);
    let mut command = C::augment_args(clap::Command::new(name)).bin_name(C::COMMAND);
    error.insert(
        ContextKind::Usage,
        ContextValue::StyledStr(command.render_usage()),
    );
    error
}
