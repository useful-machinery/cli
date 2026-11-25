# CLI output style

Conventions for every human-facing string the `useful` CLI prints: help
text, errors, warnings, progress, reports, and prompts. Machine surfaces (JSON
documents, schema files, protocol messages) are governed by their contracts,
not this guide.

## Voice

Register follows the **subject** of the message:

- **Second person when the subject is the user** — identity, account, sign-in
  state, permissions. Contractions are allowed here.
  - `! You're not signed in to Useful Machinery.`
- **Neutral voice when the subject is a thing** — workflows, runs, artifacts,
  checks, the runner. No contractions.
  - `state: succeeded`, `Git 2.54.0 is available.`
- **Remedies are imperative** in either register: `Sign in first.`,
  `Start a new run instead.`

Banned padding: "sorry", "unexpectedly", "Oops", and "failed to"/"could not"
chains. Use "cannot" only for invariant refusals (a thing that will never
work), plain fragments for circumstantial failures (a thing that might work
next time).

## Errors

An error has two parts: a **diagnostic line** and an optional **remedy block**.

```
error: cannot retry run: attempt 1 succeeded

A succeeded run cannot be retried. Start a new run instead:
  useful workflow run create --path <DIR> --execution-root <PATH> --run-dir <NEW_DIR>
```

Diagnostic line rules:

- The prefix is lowercase `error:` — matching clap's usage errors, which
  appear in the same sessions and cannot be restyled.
- The message is a fragment: lowercase, no trailing period. Errors usually end
  in paths or identifiers that users copy; a period would corrupt them.
- Causes chain inline with colons, outermost first, curated to about three
  links. Each link is a bare verb phrase naming the attempted operation —
  `error: read runner credential file /path/cred.json: no such file or
  directory`. The `error:` prefix announces failure once; links never repeat
  "failed to".
- Platform leaves (OS error strings) render verbatim, capitalization and all.
- Name the thing that failed: path, endpoint, file, identifier. A diagnostic
  the user cannot act on ("invalid runner credential file" — which file?) is a
  bug.

Remedy block rules:

- Separated from the diagnostic by one blank line.
- Full imperative sentences. Commands go on their own indented line:

```
! You must sign in before managing Useful Machinery organizations.

Run:
  useful account login
```

- Every dead end gets a remedy or an explicit statement that none exists.
- Internal codes and stage names never appear mid-sentence; a machine code may
  appear only as a labeled data field (`code: source_unavailable`).

Before and after:

| Before | After |
|---|---|
| `Error: workflow retry rejected: latest_attempt_succeeded at attempt 1: A succeeded run cannot be retried; create a new run.` | the diagnostic + remedy split shown above |
| `artifact_directory_unavailable: The artifact directory is unavailable. (artifact directory)` | `error: artifact directory unavailable: /path/no-such-artifacts` |
| `Sign-in failed during existing_credential_check: unreachable (connection).` | `error: sign in: connect to https://api.usefulmachinery.com: connection refused` |

## Streams and exit codes

**stdout carries the product; stderr carries commentary about producing it.**

- Reports, state dumps, JSON, and execution logs go to stdout. A
  `workflow run create` step log is the product of running a workflow. The answer
  `account show` prints is the status you asked for, even when the answer is
  "not signed in".
- Errors, warnings, and transient progress ("Connecting…") go to stderr.
- Exit codes follow the registry below; the verdict never rides only on prose.

| Code | Registry name | Meaning |
|---:|---|---|
| 0 | `Success` | The command completed successfully. |
| 1 | `GeneralFailure` | The command failed without a more specific registered class. |
| 2 | `UsageError` | The command line is invalid; this is clap's usage-error code. |
| 3 | `AuthenticationRequired` | The command requires a signed-in identity. |
| 4 | `Unavailable` | Useful Machinery is unreachable or the request is temporarily rate limited. |
| 5 | `RunnerRecoveryRequired` | Runner Serve stopped non-admitting for operator recovery. |
| 6 | `Conflict` | A GitLab connection mutation conflicts with current authority or a request key. |
| 7 | `CandidateUnavailable` | A GitLab credential candidate cannot be activated. |
| 8 | `IdentityMismatch` | The reviewed GitLab provider identity does not match the expected user. |
| 130 | `Interrupted` | The command was interrupted by the user. |
| 143 | `Terminated` | The command received a termination request. |

CLI code uses `exit_code::ExitCode` rather than numeric process-exit literals.

## Reports

The report template: **verdict line → data fields → blank line → remedy —
and nothing after the remedy.** No trailing reassurances.

```
✗ Workflow definition is invalid.
workflow: empty-command-program.yaml
code: invalid_workflow_structure
location: workflow

Correct the workflow fields to match the workflow contract.
```

- Data keys are lowercase (`workflow:`, `state:`, `attempt:`), as are table
  headers and section rules (`── summary ──`). Capitalization is reserved for
  sentences: verdicts and remedies.
- Symbols: `✓`/`✗` for verdicts, `!` for attention, `·` as inline field
  separator, `──` for section rules. UTF-8 terminals are assumed.

## Terminology

One name per concept, used everywhere:

| Term | Meaning |
|---|---|
| run | the durable unit of workflow work (lives in a run directory) |
| attempt | one execution of a run |
| workflow definition | the workflow YAML (never "bundle") |
| run directory | where a run records its attempts |
| sign in / sign out | the prose verbs; the commands stay `login`/`logout` |

Banned from human prose:

- **"durable"** — architecture, not user vocabulary. Explain once in long help
  that a run directory records every attempt so runs can be inspected and
  retried.
- **Version markers** — "Workflow V1", "Artifact Set V1", "schema-version-1",
  "Schema 1". They belong to machine surfaces (`schemaVersion: 1`, JSON
  documents, schema files). `✗ Workflow V1 definition is invalid.` becomes
  `✗ Workflow definition is invalid.`
- **snake_case identifiers mid-sentence** — codes are data fields only.

## Help text

- Summaries are verb-first, sentence case, no trailing period, and state
  **purpose only**. Cardinality and contract bounds live in flags and long
  help: `List one page of organization members` becomes
  `List organization members`.
- Command verbs: **show** prints one thing; **list** prints a collection;
  **view** is interactive; **validate**/**retry** are literal.
  "Inspect" is retired — it hedges between show and view.
- Family summaries name the domain, not a verb list (the Commands list below
  already enumerates): `Validate, run, retry, and inspect local Workflow V1
  definitions` becomes `Work with local workflow definitions and runs`.
- Argument descriptions are **role-first**; preconditions come second or as
  behavior, never as a leading adjective:
  `Nonexistent durable directory for exactly one workflow run` becomes
  `Directory to create for this run (must not already exist)`.
- **Option help identity:** Help is word-identical for occurrences of the same
  semantic option identity, not merely for options with the same long spelling.
  An identity consists of the option's role and any repository-owned parameter
  that changes its behavior or contract. Compose recurring identities from one
  shared argument definition instead of copying local help. Parameterized
  identities may vary their help: `JsonArgs<F>` names each JSON result family,
  its streaming variant describes newline-delimited events, and
  `PaginationArgs<MAX>` states the selected `--limit` bound. A command-local
  option that happens to reuse a long spelling for a different concept is a
  different identity and need not have equal help.
- Value placeholders are semantic nouns (`<WHEN>`, `<PATH>`); enumerations
  appear only in `[possible values:]`; sentinel values like `-` are explained
  in the description; static defaults appear only in `[default:]`, dynamic
  defaults in prose.
- Contract-grade precision (snapshot semantics, eligibility rules, mode
  selection) goes in after-help sections, in full sentences — the model is
  `workflow run create`'s "Interactive mode:" section.

## Command grammar

- **Command list order:** list each group's explicit subcommands alphabetically
  by their rendered command token (including nested noun groups). Clap's
  generated `help` entry follows the explicit commands, last. This is a
  presentation rule, not a change to command behavior.

A **command group** is a command path that has subcommands. A **leaf** is a
command path with no subcommands. An entity family's leaf set consists of the
action leaves directly below its command group; a nested noun group starts a
separate entity family.

### Command names

- **Noun number:** every command-group token is a singular noun. Compound group
  names have a singular head noun (`input-set`, `join-key`).
  There are no plural exceptions. The one number-neutral
  name is `linear` (a proper noun); add any future
  number-neutral or irregular spelling here rather than inferring it. A provider
  such as GitHub or GitLab is an argument of `org integration`, not a group. In particular, the canonical singular group tokens are `identity`,
  `input`, `invitation`, and `member`, never `identities`, `inputs`,
  `invitations`, or `members`.
- **Verb lexicon:** the final token of every leaf below a command group is one
  of this closed set: `accept`, `add`, `answer`, `approve`, `archive`,
  `authorize`, `cancel`, `connect` (joins a service to its owner by the
  provider's sign-in or by a token), `create`, `credentials`, `deauthorize`, `decline`,
  `delete`, `disable`, `disconnect` (ends what `connect` joined), `doctor`,
  `download`, `drain`, `enable`, `end`, `event`,
  `hand-back`, `interrupt`, `issue`, `leave`, `link`, `list`, `login`,
  `logout`, `pause`, `propose`, `prune` (removes what a runner keeps on its host,
  and without `--yes` reports it), `publish`, `reconnect`, `reference`, `release`,
  `remove`, `replay`, `restore`, `resume`, `retry`, `revoke`, `rotate`,
  `schema`, `seal`, `serve`, `show`, `signup`, `sync`, `test`, `unarchive`,
  `unpause`, `update`, `upgrade`, `upload`, `validate`, `version`, `view`, `watch` (follows a
  live process and redraws until left; `view` shows a recorded one). A new leaf
  verb requires an amendment to this list; an existing command is not precedent
  for adding one.
- **Minting:** choose the creation verb from the immediate sibling leaf set. If
  that set contains `revoke`, the creation leaf is `issue`; otherwise it is
  `create`. This makes bearer secrets and capabilities, which can be
  withdrawn, `issue`/`revoke` pairs. The rule governs what the deployment
  mints, a secret or capability it issues. A leaf that begins a ceremony the
  member completes at a third party is not a minting leaf: `account
  integration connect PROVIDER` begins an OAuth consent and `org integration
  connect PROVIDER` a provider's installation or authorization, and each is
  named `connect` since it joins a service to its owner.
- **Update:** a leaf that changes an entity's attributes is named `update`,
  including when the name is the only one it changes: a name changes through
  `update` (`runner pool update POOL --name NAME`). There is no `rename` verb.
- **Unbinding:** a leaf whose operation severs an existing binding is named
  `remove`, except that the leaf ending what `connect` joined is `disconnect`
  (`account integration disconnect`, `org integration disconnect`). `detach`
  is a prohibited command verb.

### Groups and flags

- **Family summaries:** use `Manage <domain>` if any descendant leaf mutates
  remote state; otherwise use `Work with <domain>`. Do not use `Administer` or
  `Discover`. `Work with local workflow definitions and runs` is the model for
  a non-mutating family.
- **Entity-identifier flags:** a long flag that names an entity of the tree
  is the singular entity name without `-id`: `--org`, `--project`, `--pool`,
  `--runner`, `--integration`, `--definition`, `--webhook`, `--run`. It takes
  the entity's ID and, where the entity has one, its exact name, slug or
  subject. The options still spelled `-id` take a bare identifier that no name
  stands for: `--repository-id` of `org integration repository list` (the
  provider's repository ID), `--expected-provider-user-id` of `org integration
  connect` and `reconnect`, and `--delegator-principal-id` of the `org
  integration` leaves that change a connection and of `org create`.
- **Destructive confirmation:** a leaf requires `--yes` when its final token is
  `delete`, `decline`, `disconnect`, `end`, `leave`, `remove`, or `revoke`,
  except `project webhook secret revoke`, which ends only the overlap of a
  secret a rotation already replaced and takes no `--yes`. Of other leaves only
  `authorize` and `deauthorize` of `account integration` and `org integration`
  have `--yes`, and `project update`, where it confirms `--clear-repository`
  alone. Those and `account integration disconnect` check `--yes` themselves,
  refusing its absence as clap does but with the statement of what the command
  will do; since the refusal comes before the name is looked up, it states that
  for an OAuth grant, a native grant and your token alike, or, for `org
  integration authorize` and `deauthorize` given `--project`, for an
  organization's connection authorization alone, and the leaf states only the
  lines of what it acts on before it acts. `account integration authorize` and
  `deauthorize` given `--runner` without `--yes`, where standard input and
  standard error are terminals and `--json` is absent, make that statement and
  ask a `[y/N]` question instead of refusing. This set covers
  permanent deletion, departure, delegation or invitation closure, and
  operations that invalidate a binding, credential, or live access. Reversible
  runner mode changes, including `runner disable` and `runner drain`, are not
  destructive and do not take `--yes`.
- **Common flag order:** whenever they co-occur, common flags appear in this
  relative order: `--json`, then `--api-key-file`, then
  `--allow-insecure-http`. Other arguments and flags do not affect this
  relative-order check.
- **Pagination:** every `list` leaf takes `--cursor` and `--limit` and
  includes this exact after-help section (once per leaf), except for the
  specific leaves below:

```
Pagination:
  This command returns one page. Pass --cursor <CURSOR> to continue.
```

  `runner join-key list` reads the join keys, the runners and each runner's
  single-runner keys to their last pages and prints them as one list, so it
  has no continuation to offer.

  `org integration list` reads every page of each provider's connection list and
  prints them as one list, so it has no continuation to offer: an organization
  holds few connections, and GitLab's are capped at 100.

  `org integration repository list` pages a GitLab connection's repositories, but
  of a GitHub binding it cannot offer bounded pagination: the public GitHub
  installation-repository API endpoint accepts neither a limit nor a cursor and
  returns an array with no continuation cursor. The repository-discovery
  endpoint also collects the provider's selection before returning it.
  Client-side slicing would still require fetching the entire unbounded
  response and would misrepresent the API's continuation semantics, so the leaf
  refuses `--limit` and `--cursor` for a GitHub binding and its after-help says
  so. Do not page a binding's repositories until the API supports it; the
  exception does not make large lists safe.

  `workflow definition list` prints every definition the local `useful` home
  holds and then every one of the project in effect, in one listing: it reads
  each page of the project's definitions itself, since a list that merges two
  places cannot page one of them. `workflow run list` is no exception: it pages
  the Cloud runs of the organization in effect, which have no end, and prints
  the runs under the home, which are few, before the first page alone, so a
  `--cursor` continues the Cloud half and lists no local row again. Each of its
  rows is led by where the run executes.

  `account integration list` reads every page of the member's grants itself
  and prints them in one listing, followed by the providers the member holds
  no grant of and then the member's tokens: that closing list is true only of
  the whole set, so a page of it would misreport what the member holds. A
  member holds a few grants, one per provider in the normal case, so the whole
  set is small. `account integration show INTEGRATION` prints one grant, and
  for an OAuth grant the newest tokens issued from it: `--uses N` is how many,
  not a page size, and there is no cursor to follow.
