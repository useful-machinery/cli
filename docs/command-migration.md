# Command migration

This release replaces the command tree of `useful`. The root holds five nouns, `account`,
`org`, `project`, `runner` and `workflow`, and `version`; every other command nests under
the noun that owns it. The change is one clean break: no earlier command path, hidden
spelling or option spelling still parses, and none prints a notice naming its replacement.
An earlier spelling is a usage error like any unknown one.

This document maps each command of the earlier tree to its replacement, then lists the
commands retired with no replacement, the hidden earlier spellings, the options respelled
or retired, and each behavior change.

## Earlier commands and their replacements

Every visible command of the earlier tree, with the command or commands of this release
that replace it. A row whose two sides match names a command that keeps its path; its
arguments may still have changed, as the later sections say.

| Earlier command | Replacement |
|---|---|
| `useful account deletion cancel` | `useful account restore` |
| `useful account deletion request` | `useful account delete` |
| `useful account signup` | `useful account signup` |
| `useful account update` | `useful account update` |
| `useful artifact download` | `useful workflow run artifact download` |
| `useful artifact list` | `useful workflow run artifact list` |
| `useful artifact validate` | `useful workflow run artifact validate` |
| `useful auth identity link` | `useful account identity link` |
| `useful auth identity list` | `useful account identity list` |
| `useful auth identity remove` | `useful account identity remove` |
| `useful auth login` | `useful account login` |
| `useful auth logout` | `useful account logout` |
| `useful auth status` | `useful account show` |
| `useful connection github installation list` | `useful org integration list` |
| `useful connection github installation remove` | `useful org integration disconnect` |
| `useful connection github repository list` | `useful org integration repository list` |
| `useful connection github setup begin` | `useful org integration connect` |
| `useful connection github setup complete` | `useful org integration connect` |
| `useful connection gitlab create` | `useful org integration connect` |
| `useful connection gitlab credential activate` | `useful org integration connect` |
| `useful connection gitlab credential cancel` | Retired |
| `useful connection gitlab credential create` | `useful org integration connect` |
| `useful connection gitlab credential show` | Retired |
| `useful connection gitlab list` | `useful org integration list` |
| `useful connection gitlab remove` | `useful org integration disconnect` |
| `useful connection gitlab repository link` | `useful org integration repository add` |
| `useful connection gitlab repository list` | `useful org integration repository list` |
| `useful connection gitlab repository remove` | `useful org integration repository remove` |
| `useful connection gitlab show` | `useful org integration show` |
| `useful connection linear authorization create` | `useful org integration connect` |
| `useful connection linear authorization show` | `useful org integration show` |
| `useful connection linear authorization wait` | `useful org integration connect` |
| `useful connection linear delete` | `useful org integration disconnect` |
| `useful connection linear list` | `useful org integration list` |
| `useful connection linear remove` | `useful org integration disconnect` |
| `useful connection linear show` | `useful org integration show` |
| `useful connection linear state list` | `useful org integration team show` |
| `useful connection linear team list` | `useful org integration team list` |
| `useful delegation accept` | `useful account delegation accept` |
| `useful delegation end` | `useful account delegation end` |
| `useful delegation list` | `useful account delegation list` |
| `useful delegation propose` | `useful account delegation propose` |
| `useful delegation show` | `useful account delegation show` |
| `useful integration authorize` | `useful account integration authorize`, `useful org integration authorize` |
| `useful integration connect` | `useful account integration connect`, `useful account integration reconnect`, `useful org integration connect`, `useful org integration reconnect` |
| `useful integration deauthorize` | `useful account integration deauthorize`, `useful org integration deauthorize` |
| `useful integration list` | `useful account integration list`, `useful account integration show`, `useful org integration list`, `useful org integration show` |
| `useful integration revoke` | `useful account integration disconnect`, `useful org integration disconnect` |
| `useful invitation accept` | `useful account invitation accept` |
| `useful invitation decline` | `useful account invitation decline` |
| `useful invitation list` | `useful account invitation list` |
| `useful invitation preview` | `useful account invitation show` |
| `useful organization audit list` | `useful org audit list` |
| `useful organization create` | `useful org create` |
| `useful organization deletion cancel` | `useful org restore` |
| `useful organization deletion request` | `useful org delete` |
| `useful organization invitation issue` | `useful org invitation issue` |
| `useful organization invitation list` | `useful org invitation list` |
| `useful organization invitation revoke` | `useful org invitation revoke` |
| `useful organization leave` | `useful org leave` |
| `useful organization list` | `useful org list` |
| `useful organization member history` | `useful org member event list` |
| `useful organization member list` | `useful org member list` |
| `useful organization member remove` | `useful org member remove` |
| `useful organization member update` | `useful org member update` |
| `useful organization show` | `useful org show` |
| `useful organization update` | `useful org update` |
| `useful project action create` | Retired |
| `useful project action delete` | Retired |
| `useful project action disable` | Retired |
| `useful project action enable` | Retired |
| `useful project action list` | Retired |
| `useful project action show` | Retired |
| `useful project action update` | Retired |
| `useful project archive` | `useful project archive` |
| `useful project create` | `useful project create` |
| `useful project list` | `useful project list` |
| `useful project rename` | `useful project update` |
| `useful project repository remove` | `useful project update` |
| `useful project repository set` | `useful project update` |
| `useful project repository show` | `useful project show` |
| `useful project repository update` | `useful project update` |
| `useful project runner-pool remove` | `useful project pool remove` |
| `useful project runner-pool set` | `useful project pool add` |
| `useful project show` | `useful project show` |
| `useful project unarchive` | `useful project unarchive` |
| `useful project webhook create` | `useful project webhook create` |
| `useful project webhook delete` | `useful project webhook delete` |
| `useful project webhook delivery list` | `useful project webhook delivery list` |
| `useful project webhook delivery replay` | `useful project webhook delivery replay` |
| `useful project webhook delivery show` | `useful project webhook delivery show` |
| `useful project webhook disable` | `useful project webhook disable` |
| `useful project webhook enable` | `useful project webhook enable` |
| `useful project webhook list` | `useful project webhook list` |
| `useful project webhook revoke-previous-secret` | `useful project webhook secret revoke` |
| `useful project webhook rotate-secret` | `useful project webhook secret rotate` |
| `useful project webhook show` | `useful project webhook show` |
| `useful project webhook test` | `useful project webhook test` |
| `useful project webhook update` | `useful project webhook update` |
| `useful publication create` | `useful workflow run publication create` |
| `useful publication list` | `useful workflow run publication list` |
| `useful publication show` | `useful workflow run publication show` |
| `useful run cancel` | `useful workflow run cancel` |
| `useful run continue` | `useful workflow run retry` |
| `useful run input delete` | `useful workflow run input delete` |
| `useful run input download` | `useful workflow run input download` |
| `useful run input show` | `useful workflow run input show` |
| `useful run input-set create` | `useful workflow input-set create` |
| `useful run input-set delete` | `useful workflow input-set delete` |
| `useful run input-set seal` | `useful workflow input-set seal` |
| `useful run input-set show` | `useful workflow input-set show` |
| `useful run input-set upload` | `useful workflow input-set upload` |
| `useful run linear history` | `useful workflow run linear list` |
| `useful run linear show` | `useful workflow run show` |
| `useful run list` | `useful workflow run list` |
| `useful run retry` | `useful workflow run retry` |
| `useful run show` | `useful workflow run show` |
| `useful runner activation issue` | `useful runner join-key issue` |
| `useful runner activation list` | `useful runner join-key list` |
| `useful runner activation revoke` | `useful runner join-key revoke` |
| `useful runner create` | `useful runner join-key issue` |
| `useful runner credential list` | `useful runner credential list` |
| `useful runner credential retire` | `useful runner credential revoke` |
| `useful runner credential revoke` | `useful runner credential revoke` |
| `useful runner delete` | `useful runner delete` |
| `useful runner disable` | `useful runner disable` |
| `useful runner doctor` | `useful runner doctor` |
| `useful runner drain` | `useful runner drain` |
| `useful runner enable` | `useful runner enable` |
| `useful runner enroll` | `useful runner serve` |
| `useful runner integration sync` | `useful runner sync` |
| `useful runner join-key issue` | `useful runner join-key issue` |
| `useful runner join-key list` | `useful runner join-key list` |
| `useful runner join-key revoke` | `useful runner join-key revoke` |
| `useful runner list` | `useful runner list` |
| `useful runner move` | `useful runner update` |
| `useful runner pool create` | `useful runner pool create` |
| `useful runner pool delete` | `useful runner pool delete` |
| `useful runner pool list` | `useful runner pool list` |
| `useful runner pool rename` | `useful runner pool update` |
| `useful runner pool show` | `useful runner pool show` |
| `useful runner prune` | `useful runner prune` |
| `useful runner rename` | `useful runner update` |
| `useful runner serve` | `useful runner serve` |
| `useful runner show` | `useful runner show` |
| `useful runner status` | `useful runner show` |
| `useful runner watch` | `useful runner watch` |
| `useful service-principal create` | `useful account service create` |
| `useful service-principal credential issue` | `useful account service key issue` |
| `useful service-principal credential list` | `useful account service key list` |
| `useful service-principal credential revoke` | `useful account service key revoke` |
| `useful version` | `useful version` |
| `useful workflow definition cloud archive` | `useful workflow definition archive` |
| `useful workflow definition cloud delete` | `useful workflow definition delete` |
| `useful workflow definition cloud disable` | `useful workflow definition disable` |
| `useful workflow definition cloud enable` | `useful workflow definition enable` |
| `useful workflow definition cloud evaluation list` | `useful workflow definition evaluation list` |
| `useful workflow definition cloud evaluation show` | `useful workflow definition evaluation show` |
| `useful workflow definition cloud list` | `useful workflow definition list` |
| `useful workflow definition cloud set-principal` | `useful workflow definition update` |
| `useful workflow definition cloud show` | `useful workflow definition show` |
| `useful workflow definition cloud unarchive` | `useful workflow definition unarchive` |
| `useful workflow definition disable` | `useful workflow definition disable` |
| `useful workflow definition enable` | `useful workflow definition enable` |
| `useful workflow definition list` | `useful workflow definition list` |
| `useful workflow definition publish` | `useful workflow definition publish` |
| `useful workflow definition show` | `useful workflow definition show` |
| `useful workflow definition validate` | `useful workflow validate` |
| `useful workflow reference` | `useful workflow reference` |
| `useful workflow run answer` | `useful workflow run answer` |
| `useful workflow run approve` | `useful workflow run approve` |
| `useful workflow run cancel` | `useful workflow run cancel` |
| `useful workflow run create` | `useful workflow run create` |
| `useful workflow run event` | `useful workflow run event` |
| `useful workflow run hand-back` | `useful workflow run hand-back` |
| `useful workflow run interrupt` | `useful workflow run interrupt` |
| `useful workflow run lift` | `useful workflow run unpause` |
| `useful workflow run list` | `useful workflow run list` |
| `useful workflow run release` | `useful workflow run release` |
| `useful workflow run restart` | `useful workflow run upgrade` |
| `useful workflow run resume` | `useful workflow run resume`, `useful workflow run retry` |
| `useful workflow run retry` | `useful workflow run retry` |
| `useful workflow run show` | `useful workflow run show` |
| `useful workflow run status` | `useful workflow run show` |
| `useful workflow run stop` | `useful workflow run pause` |
| `useful workflow run upgrade` | `useful workflow run upgrade` |
| `useful workflow run view` | `useful workflow run view` |
| `useful workflow run withdraw` | `useful workflow run cancel` |
| `useful workflow schema` | `useful workflow schema` |
| `useful workflow validate` | `useful workflow validate` |

## Retired with no replacement

- `useful connection gitlab credential cancel`: the candidate token is part of
  `useful org integration connect` and `useful org integration reconnect`, and interrupting
  either command cancels its candidate.
- `useful connection gitlab credential show`: no command reads a GitLab credential
  candidate, which lives no longer than the `create` or `reconnect` that staged it.
- `useful project action create`, `delete`, `disable`, `enable`, `list`, `show` and
  `update`: Google Docs actions were removed, so a project has no actions to manage.

## Hidden earlier spellings

The earlier tree also parsed 19 hidden spellings, each printing a warning that named its
replacement. None of them parses in this release.

| Hidden earlier spelling | Replacement |
|---|---|
| `useful auth agent-login authorize` | `useful account integration authorize` |
| `useful auth agent-login deauthorize` | `useful account integration deauthorize` |
| `useful auth agent-login import` | `useful account integration connect` |
| `useful auth agent-login list` | `useful account integration list` |
| `useful auth agent-login reconnect` | `useful account integration reconnect` |
| `useful auth agent-login revoke` | `useful account integration disconnect` |
| `useful auth agent-login show` | `useful account integration show` |
| `useful auth credential status` | `useful account integration list` |
| `useful auth grant create` | `useful account integration connect` |
| `useful auth grant list` | `useful account integration list` |
| `useful auth grant revoke` | `useful account integration disconnect` |
| `useful auth grant uses` | `useful account integration show` |
| `useful grant authorize` | `useful account integration authorize` |
| `useful grant create` | `useful account integration connect`, `useful account integration reconnect` |
| `useful grant deauthorize` | `useful account integration deauthorize` |
| `useful grant list` | `useful account integration list`, `useful account integration show` |
| `useful grant revoke` | `useful account integration disconnect` |
| `useful runner agent-login sync` | `useful runner sync` |
| `useful runner grant sync` | `useful runner sync` |

## Options respelled or retired

An option the earlier tree spelled differently takes the spelling below, and the earlier
spelling stops parsing. An option this section does not name, such as `--expected-version`,
`--idempotency-key`, `--allow-insecure-http`, `--limit` or `--cursor`, keeps its spelling on
the command that replaces its command.

| This release | Earlier tree |
|---|---|
| `--org ORG` | The leading `ORGANIZATION` argument of commands that act within an organization; `--organization` of `integration connect` and `runner serve`; `--organization-id` of `runner doctor`; the organization `--cloud ORGANIZATION` named |
| `--project PROJECT` | The `PROJECT` argument of commands that act within a project; `--project-id`; `--project` of `workflow run create` and `workflow definition publish` |
| `--pool POOL` | `--pool-id`; the `POOL` arguments of `project runner-pool set` |
| `--runner RUNNER` | `--runner-id` of `runner doctor`; the `RUNNER` argument of `integration authorize`, `integration deauthorize`, `runner credential revoke` and `runner credential retire` |
| `--integration INTEGRATION` | `--installation-id` and `--gitlab-connection-id` of `project create` and `project repository set`; the `INTEGRATION` argument of `connection gitlab repository link`, `connection gitlab repository remove` and `connection linear state list` |
| `--repository REPOSITORY` | `--repository-id` of `project create` and `project repository set` |
| `--installation ID` | `--provider-installation-id` of `connection github setup complete` |
| `--input-set INPUT_SET` | `--input-set-id` of `workflow run create` |
| `--account ACCOUNT` | `--principal-id` of `organization invitation issue`; it still takes a principal ID (`prn_…`) |
| `--run-as SERVICE` | The `PRINCIPAL` argument of `workflow definition cloud set-principal` |
| `--name NAME` | `--display-name` of `account update`, `organization create`, `organization update` and `service-principal create`; `--clear-name` replaces `--clear-display-name` of `account update` |
| `--key-file PATH\|-` | `--api-key-file` of `service-principal create` and `service-principal credential issue`; `--activation-file` of `runner create` and `runner activation issue`; `--join-key-file` of `runner join-key issue` |
| `--pause-before STEP` | `--stop-before` of `workflow run create` |
| `--state-updates` | `--enable-state-updates` of `connection linear authorization create`; `org integration connect linear` and `org integration reconnect` both take it |
| `--api-key-file PATH\|-` | `--service-api-key-file`, the service API key option of every command that takes one |

Retired, with no option in their place:

- `--cloud`: a run or definition is found by its ID, where one is made is `--on`, and its
  organization is `--org`.
- `--cloud-to` and `--cloud-new`: `workflow definition publish --on project` takes `--to` and
  `--new` for its Cloud target.
- `--no-owner`: `workflow run create --on project` starts a run with no owner on the
  project's runner pools.
- `--org` as the option that turned a `useful integration` command to the organization's
  side: what acts as you is `useful account integration`, and what acts as the organization
  is `useful org integration`, in the organization in effect.
- `--replace` of `integration connect`: `reconnect` signs in again or stores a token's next
  version.
- `--connection-id` of `integration authorize` and `deauthorize`: the connection is the
  `INTEGRATION` argument of `useful org integration authorize` and `deauthorize`.

## Behavior changes

### Context and subjects

- A command that acts within an organization takes it from `--org`, then `USEFUL_ORG`, then
  the project of the current checkout, then your only active membership; with several
  memberships and nothing naming one, it exits 2, names `--org` and lists your
  organizations.
- A command that acts within a project takes it from `--project`, then `USEFUL_PROJECT`, each
  a project ID or the exact name of a project of the organization in effect, then the current
  checkout, whose Git remote must name the repository of exactly one project, and that project
  must belong to the organization in effect.
- Nothing stores a default organization or project, so no earlier command changes what a
  later one acts on.
- A command that changes or removes an organization or a project itself names it as its
  argument, as `useful org delete ORG --yes` does, and never takes it from the context.
- A command whose subject is on this machine finds it by path, then under the `useful`
  home, and asks Cloud only when the home holds nothing, so it makes no request and needs no
  sign-in.
- `useful workflow run show RUN` looks for a run ID or a subject under the `useful` home and
  then in Cloud in the organization in effect, which alone is read: no project narrows it.
  An ID the home lacks is the Cloud run of that ID. A subject the home lacks is the newest run,
  for each definition, whose subject claim names it, among the organization's 500 newest live
  runs and, when none is live and every live run was read, its 500 newest ended ones; an
  older run is found by its ID.
  Signed out or with no organization in effect, a run the home lacks is `run_not_found`
  saying Cloud was not asked. `useful workflow run view RUN` looks under the home alone.
- A JSON document that carries a `command` member names the command of this release that
  printed it; the documents otherwise keep their shape.

### Account

- `useful account signup` signs in first when this device has no session, as
  `useful account login` does, so a new user runs one command. With `--json` it starts no
  sign-in and reports `unauthenticated`, as before.
- `useful account show`, when you are signed in, also prints the organization and project in
  effect and where each came from (an option, the environment, the checkout or your only
  membership), or that none is; with `--json` they are the members `organizationInEffect`
  and `projectInEffect`. It takes `--org` and `--project`, and what it finds never changes its
  exit status: a source it cannot use is named on standard error.
- `useful account integration connect` with no provider, `--all` or `--workflow` refuses and names
  the three choices, where the earlier `integration connect` signed in to every missing provider.
- `useful account integration connect --workflow FILE --runner RUNNER` passes over a coding agent for
  which the runner, named by its ID or exact name, reported its host's own sign-in on a grant
  of yours authorized for it, since the runner would not use the grant. It changes nothing for
  a provider Cloud holds no such report of: one you hold no grant of, a grant not authorized
  for that runner, or an OAuth provider.
- `useful account integration show INTEGRATION` replaces `integration list INTEGRATION`, which
  doubled as show.
- `useful account integration reconnect INTEGRATION` replaces `integration connect --replace`, keeping the
  grant's ID and runners. It asks nothing and takes the source options of `create` that suit
  the grant's provider: `--login`, `--device` and `--from-file` for Codex, `--token-file` for
  Claude Code, and `--no-wait` and `--timeout` for an OAuth provider. `useful account integration
  connect PROVIDER` no longer replaces a grant you hold: it refuses and names `reconnect` with
  each grant's ID, on a terminal too.
- `useful account integration connect --workflow` no longer signs in to a provider whose grants need
  reconnecting, nor asks about one: it passes the provider over and names `useful account
  integration reconnect` with each such grant's ID. `useful runner doctor --workflow --connect` is
  gone, its `--replace` with it, so `useful account integration connect --workflow` is the one
  command that signs in to what a workflow needs; its `--workflow` also takes a tree
  directory, which stands for the tree's `workflow.yaml`.
- `useful account integration authorize` and `deauthorize` take the runner as `--runner RUNNER`,
  by its ID or exact name, and without it refuse and list the runners you may name instead of
  prompting. Authorizing or deauthorizing every runner at once is no longer a choice: run the
  command once for each runner. Without `--yes`, on a terminal, they state what acting does
  and ask whether to go on.
- `useful integration` is split by owner. `useful account integration` acts as you: on your
  grants and on your own token of a token service. `useful org integration` acts as the
  organization in effect: on its connections, its tokens and its connection authorizations.
  No option moves a command from one side to the other.
- `useful account integration list` shows your grants and your tokens and nothing of an
  organization's, which `useful org integration list` shows.
- `connect` of a token service whose token you already hold refuses and names `reconnect`,
  on a terminal too, where `integration connect` asked or took `--replace`.
- `disconnect` replaces `revoke`, for a grant and for a token.

### Organizations

- `useful org list` marks the organization in effect and says which source named it, and
  its JSON document gains the member `organizationInEffect`.
- `useful org show` with no `ORG` shows the organization in effect.
- `useful org member update MEMBER` and `useful org member remove MEMBER` take a membership
  ID or an email address that is one member's verified linked address; an address no member
  holds is not found (exit 1), and an address two members hold is refused (exit 2) until you
  name the membership ID.
- `useful org integration list` lists the connections to GitHub, GitLab and Linear in one
  list and reads every page of each, so it takes no `--limit` or `--cursor`; `--provider`
  reads one provider's list. It names a provider it could not list, because the caller may
  not read that list or the deployment does not serve it, and still succeeds when another
  provider was read.
- `useful org integration connect PROVIDER` connects GitHub, GitLab or Linear. For GitLab and
  Linear it waits until the connection is active; for GitLab it runs the earlier
  `connection gitlab create`, `credential create` and `credential activate` as one command.
- `useful org integration connect gitlab --token-file PATH --kind KIND` takes the instance as
  `--instance-url URL`, default `https://gitlab.com`, where `connection gitlab create` took
  it as an argument. It waits up to `--timeout` (default 10 minutes) for GitLab to verify the
  token, asks on the terminal for the verified identity to be confirmed, or takes
  `--expected-provider-user-id` with `--dedicated-automation`, and activates it. Every ending
  but activation cancels the candidate it staged and names `useful org integration reconnect
  INTEGRATION --token-file PATH --kind KIND`. One `--idempotency-key` covers the command: each
  request sends it with a suffix naming its step, so the key has at most 240 characters, and
  running the command again with the same key replays each step it had completed.
  `reconnect` of a GitLab connection does the same from the token's submission; to replay
  one whose activation completed, also pass the `--expected-version` its first run sent.
- `useful org integration connect github` prints the GitHub App installation page, and
  `create github --installation ID` completes the connection for that installation. It
  begins a setup session of its own, so it needs nothing from the first invocation: no
  setup session is printed or typed.
- `useful org integration show INTEGRATION` takes a connection ID, or a provider (`github`,
  `gitlab` or `linear`) that names the organization's one connection to it still in use;
  a provider that names several is refused (exit 2) until you name the connection by its ID.
  `show` also takes the ID of a Linear authorization session, which replaces
  `connection linear authorization show`. No command reads a GitLab credential candidate,
  which lives no longer than the `create` or `reconnect` that staged it.
- `useful org integration reconnect INTEGRATION` covers renewing a GitHub binding, GitLab token
  rotation and the earlier `connection linear authorization create --connection-id`, keeping
  the connection's ID and bindings.
- `useful org integration reconnect` of a GitHub binding opens no page: it completes a new
  setup session for the binding's own installation, which keeps the binding's ID, and
  refuses a binding whose installation GitHub removed, naming `create github`.
- `useful org integration connect linear` and `reconnect` of a Linear connection wait for the
  authorization themselves, which replaces `connection linear authorization wait`; `useful
  org integration show SESSION` reads a session either of them stopped observing.
- `useful org integration disconnect INTEGRATION --yes --release-workspace` replaces
  `connection linear delete`.
- `useful org integration connect`, `reconnect`, `show`, `authorize`, `deauthorize` and
  `disconnect` of a token service act on the organization's token, as the `useful integration`
  commands did with `--org`. `useful org integration list` prints the organization's tokens
  after its connections.
- `useful org integration authorize INTEGRATION --runner RUNNER --project PROJECT` replaces
  `integration authorize PROVIDER RUNNER --org ORG --project-id PROJECT`, and `deauthorize`
  likewise. The connection is named by its ID, or by its provider when one is active there.
  `--project` must be given on the command line, and without `--runner` the command refuses
  and lists the runners it could name instead of prompting.
- `useful org integration repository add REPOSITORY... --integration INTEGRATION` and
  `repository remove REPOSITORY... --integration INTEGRATION --yes` take the GitLab project IDs
  as arguments, where `connection gitlab repository link` and `repository remove` took a
  repeated `--repository-id`.
- `--expected-version` is optional on `remove`, `reconnect`, `repository add` and
  `repository remove` of a GitLab connection, where the earlier commands, `credential create`
  among them, required it: without it the command reads the connection and sends its current
  version, and a version given is sent as given.

### Projects

- Each `useful project` command acts in the organization in effect, where the earlier
  commands took `ORGANIZATION` as their first argument, and `PROJECT`, where a command takes
  one, is the project's ID or its exact name.
- `useful project show [PROJECT]` prints the repository binding in full, with no `PROJECT`
  shows the project in effect, and replaces `project repository show`: a script that read
  `.repository` of `repository show --json` reads `.project.repository` of `show --json`. A
  project with no repository is no longer an exit 1: `show` prints `repository: none` and the
  `repository_detached` blocker.
- `useful project create NAME --repository REPOSITORY` takes the project's name as its
  argument, where the earlier command took `--name`, and `REPOSITORY` as `owner/name`, a GitLab
  project's full path or the provider's repository ID. It finds the connection that reaches the
  repository: a GitHub binding in use whose installation grants it, or a GitLab connection in
  use that has it selected. When several do it exits 2 and creates nothing, and
  `--integration INTEGRATION`, by ID or as `github` or `gitlab`, replaces `--installation-id` and
  `--gitlab-connection-id` to name one.
- `useful project create --pool POOL` may be repeated: the creation carries the first pool, and
  when several are named one more request then assigns them all as the project's set.
- `useful project update PROJECT` replaces `project rename`, `repository set`, `repository
  update` and `repository remove`: `--name`, `--repository [--integration]`, `--default-branch`
  and `--clear-repository --yes` may be given together, and the command sends the repository
  change before the name. It prints outcome `updated` with `applied`, the list of
  `repository_set`, `repository_updated`, `repository_detached` and `renamed` for what it sent,
  where the earlier commands printed those words as their outcomes. When a later request fails
  after an earlier one succeeded, the result is the failure's with `applied` and the project as
  the earlier request returned it.
- `useful project pool add POOL` adds one runner pool, where the earlier
  `project runner-pool set` replaced the whole set.
- `useful project pool remove POOL --yes` removes one runner pool, where the earlier
  `project runner-pool remove` emptied the whole set.
- Adding a pool the set already holds, or removing one it does not hold, changes nothing.
  `pool add` and `pool remove` read the project and write the set they read with the one
  change, so a change another owner makes to the set between that read and the write is
  replaced.
- `useful project webhook delivery show DELIVERY` and `replay DELIVERY` take the webhook as
  `--webhook WEBHOOK`.
- `useful project webhook delivery list WEBHOOK` takes `--run RUN`, where the earlier command
  took `--run-id`.

### Runners

- `useful runner serve --join-key-file PATH|-` also reads a single-runner key, the earlier
  activation file, so the separate `runner enroll` step is gone: the start that enrolls the
  host serves it. The `--join-key` prompt and `USEFUL_RUNNER_JOIN_KEY` take either kind of key
  too, told apart by what the key holds.
- `useful runner serve` finishes an interrupted enrollment itself, so `runner enroll
  --resume` has no replacement option. An ambiguous or refused enrollment exits 1 without
  serving, and the next start, with the same key or with none, resends the same request.
- `useful runner serve --replace-credential --join-key-file PATH|-` with a single-runner key
  enrolls a second credential for the host's runner, asks the running process to switch to
  it and exits without serving; with no key it resends a staged replacement. `serve` takes
  `--json` with `--replace-credential` alone, and the report is the one `enroll
  --replace-credential --json` printed.
- The `enrolled` and `gone` documents of `runner enroll --json` are gone. The state file and
  the terminal receipt hold what they held, the start reports the runner on standard error,
  and `useful runner show` reports it once it serves.
- `useful runner doctor` checks the host alone and lists every check, so `--list-checks`,
  `--workflow`, `--grants`, `--readiness`, `--require-grants`, `--connect` and `--replace` are
  gone; `useful workflow doctor` reports what a workflow needs, and
  `useful account integration connect --workflow` signs in. Its report names each check that did not
  run with the `--check ID` that runs it, and `--json` carries them as `notRun`, each with its
  `id` and `title`, beside the unchanged `checks` and `summary`.
- `useful runner join-key issue --runner NAME` issues a single-runner key: for a new name it
  registers the runner and issues its first key, and for an existing runner it issues a new
  key and revokes the earlier one.
- `useful runner join-key issue` names another member's personal pool with
  `--member MEMBER`, a pool with `--pool POOL`, and with neither your own personal pool.
- `useful runner join-key issue` takes `--expires-in` and `--remove-after` for a pool key
  alone, since a single-runner key lives one hour.
- A single-runner key always names its runner with `--runner`: `runner create` let Cloud
  generate a name, and `join-key issue --runner` registers the name it is given.
- `--pool` or `--member` given for a runner that exists must name the pool it is in; another
  pool is a usage error that issues nothing and names `useful runner update`.
- `--member` takes a principal ID, as `runner create --member` did, a membership ID or a
  member's verified email address.
- An omitted `--remove-after` is 30 days, the longest Cloud admits; `--remove-after` was
  required.
- `useful runner join-key list` reads one request per runner beside the join keys and the
  runners, so it has no `--limit` or `--cursor` and prints no next cursor; `--json` adds the
  single-runner keys as `singleRunnerKeys` beside the pool keys' `items`.
- `useful runner join-key list` and `revoke` take `--runner RUNNER` for one runner's
  single-runner keys; `revoke` without it finds the runner that holds the key.
- Both kinds of key are written as one line of JSON; a single-runner key file was indented,
  and a file an earlier release wrote still reads.
- `useful runner credential revoke CREDENTIAL --runner RUNNER --yes` revokes at once, and
  with `--after` replaces `runner credential retire`, accepting the one-hour grace alone:
  `--after` takes `1h` or `60m`, and any other duration is a usage error that sends nothing.
  The output of a retirement is unchanged, outcome `retiring`.
- `useful runner update RUNNER` replaces `runner move` and `runner rename`, taking
  `--pool POOL`, `--name NAME` or both. With both it sends the move first and the rename last,
  each under its own key. Its result has outcome `updated` and `applied`, the names of what
  it sent, `pool` then `name`, where the earlier commands reported `moved` and `renamed`. A
  rename that fails after the move leaves the runner moved: the command exits with the
  rename's failure, and its document holds that failure's outcome, `applied` and the runner
  as moved.
- `useful runner pool create NAME` takes the pool's name as its argument, where it took
  `--name`, and `useful runner pool update POOL --name NAME` replaces `runner pool rename`
  with the same request, the same document, outcome `renamed`, and the same refusal of a
  personal pool.
- `useful runner list --pool POOL` lists the runners of one pool. It reads every page of the
  organization's runners and prints no cursor, so it refuses `--limit` and `--cursor`.
- `useful runner show` with no `RUNNER` replaces `runner status`: it asks this host's live
  runner through its control socket and prints the same status, takes `--config PATH` alone
  and has no `--json`. `--config` with a `RUNNER`, and `--org`, `--api-key-file`,
  `--allow-insecure-http` or `--json` without one, are usage errors.
- `useful runner sync` replaces `runner integration sync` with the same options, request, output
  and exit statuses.
- `useful runner serve --personal` and `--pool POOL`, which replaces `--pool-id`, register a
  host with no state in the organization in effect: `--org`, which replaces `--organization`,
  then `USEFUL_ORG`, the checkout and your only organization, where `--organization` was
  required. With none in effect the start exits 2 listing your organizations and registers
  nothing. `--org` without `--personal` or `--pool` is a usage error, as `--organization` was.
- A host that holds enrolled state, started with `--personal` or `--pool`, compares the mode
  and the pool with its registration record always and the organization only when `--org` or
  `USEFUL_ORG` names one; it still reads no sign-in and sends nothing.

### Workflows

- `useful workflow validate PATH` is the one validator; its source root defaults to the Git
  repository that holds `PATH`, and `--source-root` overrides it. A directory `PATH` is a
  tree, its own source root, so `--source-root` and `--agent-profiles` given with one are a
  usage error (exit 2).
- `useful workflow doctor PATH...` reports your grants, the organization's connections and
  the runner's authorizations in one list with the command that fixes each gap, reports a
  need the runner's host meets itself as met, exits 1 while a need is unmet, keeps
  `--source-root` and never signs in. It reads the organization and the project in effect in
  place of `--organization-id` and `--project-id`, and reads the connections and, signed in,
  your grants whenever a workflow calls for a kind, so `--readiness` and `--grants` are gone.
  `--runner RUNNER`, by ID or exact name, replaces `--runner-id` and `--require-grants`: it is
  what makes a grant count, and without it your grants are shown beside each need and judge
  nothing, and a coding agent stays `unverified`. `--api-key-file` reads the connections
  alone and is refused with `--runner`. If you are not signed in you get the report every need
  `unverified`, as `runner doctor --workflow` printed it, unless `--runner` is given, which
  exits 3. The JSON document's `command` is `useful workflow doctor`, a need's `state` gains
  `met` with `metBy` naming `host`, `grant` or `connection`, and `summary` gains `met`; the
  `--connect` stream and its `report` event are gone.
- `DEFINITION` is a definition's ID or its name. It is looked up under the `useful` home
  first, without a request, and then in the project in effect, where a name is matched among
  all the project's definitions, archived ones included; a name several definitions of one
  place hold exits 2 listing their IDs, and a definition found nowhere is
  `definition_not_found`, which says where the command looked and, when Cloud was not asked,
  whether that is because you are not signed in or because no project is in effect.
- `useful workflow definition list` lists the `useful` home's definitions and then every one
  of the project in effect, read to the last page, so it takes no `--limit` or `--cursor`;
  `--on local` or `--on project` lists one place alone. Each row says where it lives (`on`
  in JSON), and the JSON document gains `cloud`, saying whether Cloud was asked and, when it
  was not, why: `local_only`, `signed_out`, `no_project` or `unreachable`. With no `--on`,
  signed out, with no project in effect or offline, it lists the home's definitions, exits 0
  and says on standard error that Cloud was not asked.
- `useful workflow definition show DEFINITION` shows a local or a Cloud definition, and the
  JSON document's `on` says which.
- `useful workflow definition publish --on project` replaces `--cloud ORGANIZATION
  --project`, and a publish reaches Cloud only with `--on project` or a Cloud `--to`.
- `useful workflow definition publish --on project` writes no local copy and keeps no link
  to one; without `--to` or `--new` it publishes to the project's active definition of the
  tree's name, creates one when there is none, and exits 2 listing their IDs when there are
  several. With `--bindings FILE` it sends the snapshot the file makes; without it a
  publication to an existing definition sends no bindings, so Cloud carries those it holds,
  and a create sends the root's defaults. Its JSON document is `schemaVersion`, `command`,
  `outcome` (`published` or `cloud_failed`) and the `cloud` object, with no `definition` or
  `revision` of a local record. With no `--on`, a `--to` name is looked up under the home
  alone and a `--to` ID the home does not hold is published to in the project in effect;
  a publication that stays under the home refuses `--org` and `--project` with exit 2, so
  `publish DIR --org ORG --project PROJECT` without `--on project` publishes nothing. The
  local publication's document is
  unchanged, and a record's `cloudId` is written null and never set.
- `useful workflow definition enable` and `disable` keep their effect on a local definition
  named by its ID: they set the record's `enabled`, which a conductor that starts the home's
  enabled definitions reads, and make no request. Any other ID, or a name, turns a Cloud
  definition's automatic starts on or off; a name is looked up in the project alone.
- `useful workflow definition archive`, `unarchive`, `delete`, `update` and `evaluation` act
  on a Cloud definition alone: they look a name up in the project in effect and refuse an ID the
  home holds with `definition_local`, exit 1, sending nothing.
- `useful workflow definition update DEFINITION --run-as SERVICE` replaces `cloud
  set-principal`. `SERVICE` is a service principal's ID, or the display name exactly one
  service principal of the organization has, read from its member directory; a name none has
  is `not_found`, exit 1, and a name several have exits 2 listing their IDs. The JSON
  document's `command` is `useful workflow definition update` and its `outcome` stays
  `principal_set`.
- `useful workflow definition evaluation show EVALUATION` takes the definition as
  `--definition DEFINITION`, and `evaluation list DEFINITION` takes `--run RUN` where the
  earlier command took `--run-id`, the spelling `project webhook delivery list` takes for the
  same filter.
- `useful workflow input-set` leaves act in the organization in effect, and `create` in the
  project in effect, in place of the leading `ORGANIZATION` and `--project-id`; each JSON
  document keeps its members, and a refused read of the organization in effect, which
  resolves none, is written without `organizationRef`.
- `useful workflow run create --on local|personal|project` replaces `--cloud ORGANIZATION`
  and `--no-owner`: `local` runs in this process and is the default, `personal` runs in
  Cloud on your runners, and `project` runs in Cloud on the project's pools with no owner.
  A Cloud run is created in the organization and project in effect, where `--org` and
  `--project` replace `--cloud ORGANIZATION` and the Cloud project ID `--project` took. The
  definition is an ID or a name read where `--on` names, under the home alone for `local`
  and in the project alone for `personal` and `project`, where an ID is sent as given and a
  name several definitions hold exits 2 naming their IDs. An option of the other place is a
  usage error, exit 2, before anything is read: `--path`, `--execution-root`, `--run-dir`,
  `--agent-profiles`, `--pause-before`, `--owner`, `--external` and `--source-revision` with
  `--on personal` or `--on project`, and the Cloud options, `--org`, `--project`,
  `--input-set` and `--wait` among them, with `--on local`.
- `useful workflow run create --path DIR` without `--run-dir` records the run under the
  `useful` home, in `runs/<run id>/`, so it has an ID and shows in the list, and
  `--execution-root` defaults to the current directory, for a definition's run too. Only a
  tree, a directory with `workflow.yaml` directly under it, has a run record to carry an ID:
  a directory that is not a tree still needs `--run-dir`, and without it the command exits
  2 naming `--run-dir`. A `--path` run takes no subject claim, so no subject finds it; its
  ID does.
- `useful workflow run list` is one list of local and Cloud runs with a column for where
  each executes, and signed out or offline it lists the local runs and says Cloud was not
  asked. It replaces `useful run list ORGANIZATION`: the Cloud half is the organization in
  effect, narrowed to the project in effect when there is one, where `--project` replaces
  `--project-id`, and it asks for the live runs unless `--all`, where the earlier command
  asked for every state. `--state-group`, `--created-after`, `--integration-context`,
  `--limit` and `--cursor` filter and page the Cloud half alone: each is a usage error with
  `--on local`, `--state-group` is one with `--all` or `--waiting`, and `--owner`,
  `--definition` and `--drift`, which select runs under the home, are one with any of them
  or a Cloud `--on` and leave Cloud unasked. The runs under the home lead the first page
  alone. Its `--json` document is the local listing's, with `on` on every run, each Cloud
  run carrying the item as the API returned it, and a `cloud` member in place of the earlier
  `items` and `nextCursor`: `asked`, with `organizationRef`, `projectId` and `nextCursor`, or
  `reason`.
- `useful workflow run show RUN` is one view for every run and replaces `status`, and with
  `--wait` it prints once the run settles. For a local run its `--json` document is the
  `status` document with `command` `useful workflow run show`, `outcome` `shown` and `show`'s
  `position`, `attempts`, `children`, `controls` and `mirror` beside its members; a run with
  no run record, a workflow file's closure, is read with `record` and `position` null; and a
  run that cannot be read prints the `error` document `status` printed, not a `refused` one.
  `--attempt N` keeps one attempt of a local run, and `--wait` and `--timeout` follow a Cloud
  run; each is a usage error for the other kind of run. A Cloud run's `--json` document is
  the one `useful workflow run show RUN --cloud ORGANIZATION` printed, with `on` (`personal`
  for a run with an owner, `project` otherwise), `deployment` and the automatic `publication`
  added and `outcome` `pending` for what `useful run show` called `accepted`; its report holds
  every line `useful run show` printed, the Linear lifecycle binding of the earlier
  `useful run linear show` among them, and `--wait` prints the `shown` document once the run
  is final.
- `RUN` is a run ID, a subject such as an issue key, or a run directory, found under the
  `useful` home and then in Cloud.
- `useful workflow run input show`, `download` and `delete` and `useful workflow run linear
  list`, which replaces `useful run linear history`, take `RUN` and the organization in
  effect in place of `ORGANIZATION RUN`. `RUN` is a run ID or a subject, looked up in Cloud
  alone: nothing under the `useful` home is read. Their options and documents are unchanged,
  except that the Linear list document's `operation` is `list`.
- `useful workflow run artifact list` and `download` take `RUN` and the organization in
  effect in place of `ORGANIZATION RUN`, `RUN` looked up in Cloud alone as for `input`; their
  options and documents are unchanged. `useful workflow run artifact validate DIR` still reads
  no credential and makes no request, and its document's `command` is `useful workflow run
  artifact validate`.
- `useful workflow run publication create --run RUN --export NAME` and `useful workflow run
  publication show PUBLICATION --run RUN` take the run as a required `--run` and `useful
  workflow run publication list RUN` as its `RUN`, each with the organization in effect, in
  place of `ORGANIZATION RUN`; `RUN` is a run ID or a subject, looked up in Cloud alone as for
  `input`, where the earlier commands took a run ID alone. Their other options and their
  documents are unchanged.
- `useful workflow run answer` continues a local run in this command, as a Cloud run
  continues on its runner; `--record-only` keeps the earlier local behavior, and
  `--question` is needed only when several questions are open: without it such an answer is
  refused `question_ambiguous`, and an answer that leaves a question open is recorded alone
  and continues nothing. `approve` and `hand-back` continue the run the same way, and each
  of the three finds a Cloud run without `--cloud`.
- `useful workflow run pause` and `unpause` are `stop` and `lift` renamed, and `create
  --pause-before` is `--stop-before`; like `answer`, they find a Cloud run without `--cloud`.
  The records they write keep their names: `control.stop` and `control.lift`, the `stop`
  wait and the codes `stop_in_force`, `stop_not_in_force` and `stop_ambiguous`.
- `useful workflow run resume RUN` continues a run from where it stands and no longer takes
  `--from`; it keeps `--workflow` and `--execution-root`, and finds a Cloud run without
  `--cloud`, asking Cloud to continue it as `resume --cloud` did with no step.
- `useful workflow run retry RUN` reruns from the stage that failed by default, `--from STEP`
  names the steps to rerun with their dependents, as `resume --from` and `useful run continue`
  did, and `--all` reruns the whole workflow, as the earlier `retry --execution-root` and
  `useful run retry` did. With neither option an ended run that did not succeed continues
  from the stage it stood at: for a workflow of edges the step its latest attempt started
  last, and otherwise every step its latest attempt left other than succeeded, skipped or
  inherited; for a Cloud run, the first step of the position it reports. A run that names
  none is refused `continuation_step_required`, naming `--from` and `--all`. `--all` without
  `--execution-root` takes the previous attempt's execution root, with the warning that an
  earlier attempt used it, and is refused `run_waiting` on a run that waits. `retry --from`
  still records the continuation reason `resume`, and its documents name `useful workflow
  run retry`.
- `useful workflow run upgrade RUN` without `--from` moves a waiting run to its definition's
  current revision and keeps its wait, and with `--from STEP` reruns from that step under
  the new revision, as the earlier `restart --at` did. `--input-text` and `--execution-root`
  belong to `--from` and are usage errors without it. The command reads a run under the
  `useful` home alone: a run the home does not hold is `run_not_found`, since a Cloud run has
  no upgrade. Its documents name `useful workflow run upgrade`, and the successor's first
  attempt still records the continuation reason `restart`.
- `useful workflow run cancel RUN` replaces `withdraw` as well, and the recorded outcome
  still says whether the run was canceled while executing or withdrawn while waiting. A run
  a live process holds is ended by signal, where `withdraw` let its running stage finish
  first: to end one after that stage, `pause RUN --before STEP` and then `cancel`. It
  replaces `useful run cancel ORGANIZATION RUN` too, finding a Cloud run without `--cloud`:
  it reads the run, sends one that waits the withdrawal `withdraw --cloud` sent, and any
  other, or one whose runner cannot apply a withdrawal, the graceful cancellation request
  `run cancel` sent, in that command's document. `--force`, `--wait`, `--timeout` and
  `--idempotency-key` are a Cloud run's; `--force` sends the force request without reading
  the run.
- `useful workflow run interrupt RUN`, `upgrade RUN` and the hidden `event RUN` read a run
  under the `useful` home alone: a `RUN` the home does not hold is `run_not_found`, and
  `interrupt`'s says that Cloud carries no interrupt and names `cancel`. `useful workflow run
  release RUN` takes no `--cloud`: it finds a Cloud run as `answer` does and releases its
  subject claim, and records the release of a run under the home as before.
- A control command refused for the run's state keeps its code (`run_not_waiting`,
  `wait_kind_mismatch`, `run_exited` and the rest), and its message names the run's state
  and the commands that apply there.
