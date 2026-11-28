# Contributing

Thank you for your interest in Useful Machinery CLI.

## Read-only mirror

This repository is a read-only mirror. Its public Git history contains mirror commits,
so maintainers cannot merge pull requests directly into this repository.

Public Discussions are welcome for bug reports, design feedback, documentation
problems, and feature requests. Maintainers may incorporate a proposal and publish it
through the normal mirror process, but starting a Discussion does not guarantee that a
patch will be adopted.

## Adding a command

Choose the path and verb before copying an existing command. The full rules and rationale
are in [Command grammar](docs/output-style.md#command-grammar); use this decision table for
the common choices:

| Decision | Rule |
|---|---|
| Available leaf verb | Use only a verb in the [Verb lexicon](docs/output-style.md#command-names), the closed set the grammar suite admits. Amend the style guide before introducing another verb; an existing command is not precedent. `detach` is a prohibited command verb. |
| Print one / print many / interact | Use `show` / `list` / `view`. Use `validate` and `retry` for those literal operations. |
| Mint an entity | Use `issue` when the immediate sibling family contains `revoke`; otherwise use `create`. |
| Change attributes | Use `update`, also when the name is the only attribute it changes (`runner pool update POOL --name NAME`); there is no `rename` verb. |
| Join or end an integration | Use `connect` for a leaf that joins a service to its owner and `disconnect` for the leaf that ends it. |
| Sever a binding | Use `remove`, never `detach`. |

Compose recurring flags from the shared argument types in `src/cli.rs`: `JsonArgs` for
`--json`, `HttpOptions` for `--allow-insecure-http`, `PrincipalAuthenticationArgs` or
`RequiredServiceAuthenticationArgs` for `--api-key-file`, `PaginationArgs` for
`--limit` plus `--cursor`, `WaitTimeoutArgs` for `--timeout`, and `NamedInputArgs` for
named inputs. Use `CommonArgs` wherever JSON, authentication, and HTTP policy co-occur so
their relative order remains structural. Help equality follows this semantic option
identity, not the long spelling alone: the same shared type and parameterization has the
same help, while `JsonArgs` result families, streaming JSON output, and
`PaginationArgs` bounds have their repository-owned parameterized help. If a flag will
recur and has no shared type yet, introduce one rather than declaring the flag on each
leaf.

Require `--yes` for leaves ending in `delete`, `decline`, `disconnect`, `end`, `leave`,
`remove`, or `revoke`, except `project webhook secret revoke`, which takes none. Of other
leaves only `authorize` and `deauthorize` of `account integration` and `org integration`
take it, and `project update` for `--clear-repository` alone. Those and
`account integration disconnect` check it themselves.
Reversible modes such as `runner disable` and `runner drain` do not take `--yes`.

Every `list` leaf paginates unless the API-limited exception is recorded in
[`docs/output-style.md`](docs/output-style.md). For a paginated leaf, expose
`--limit` and `--cursor` together through `PaginationArgs`, which also supplies
the exact `Pagination:` after-help from the style guide. Use its bound parameter
for a family whose maximum differs from the standard 200 items.

[`cli::grammar_tests::cli_grammar_conforms`](src/cli/grammar_tests.rs) checks command
grammar across the command tree, and
[`cli::tests::customer_command_surface_is_exact_and_has_no_operator_entrypoint`](src/cli.rs)
checks the customer command paths. Help prose is not a product contract and has no
snapshot tests. Prefer structural conformance checks for cross-command rules and focused
integration tests for command behavior.

## Development checks

If you inspect or modify a local copy, run the canonical check from the repository root:

```sh
./scripts/check
```

Use Devenv 2.3.1, matching the executable pinned in `.github/workflows/check.yml`.
Devenv 2.2.2's embedded Nix evaluator can intermittently fail with invalid store paths
on fresh Linux installations; upgrading only the external Nix executable does not fix
that evaluator. To run with the exact CI version without changing your profile:

```sh
nix shell github:cachix/devenv/2418e1b43797c44de5166176622c8d8fa0149871 \
  --command ./scripts/check
```

The project uses its standalone devenv environment to provide the minimum Rust toolchain
declared in `Cargo.toml` and the pinned Node 24 line used by the private PiJsonV1
extension project. In Devenv, `USEFUL_NATIVE_FREE_NODE` points to the Node 26 executable.
`./scripts/check` enters that environment through the clean boundary
and runs the same formatting, linting, testing, source-boundary, and release packaging checks
used by CI. The canonical check performs a
locked npm install before checking the extension; run
`./scripts/check-pi-json-v1-extension` for that focused path.

To qualify a replacement `useful` executable, run the process suite from this directory.
Supply the installed executable or a launcher that forwards arguments, signals, standard
streams and exit status to the implementation.

```sh
devenv shell -- scripts/test-e2e /absolute/path/to/useful
```

The standalone Cargo project under `tests/` builds the Rust test driver and its fixtures.
It has no production crate dependency. The driver launches the supplied file for commands,
snapshots, PTYs and runner sessions. It reads expected release metadata from
`USEFUL_TEST_VERSION` and `USEFUL_TEST_BUILD_IDENTITY` (development defaults
`0.0.0-dev` and `unknown`). Set these to the version and identity used to build a release.
Pass nextest filters after the executable to run a subset. Run the full selection on each
supported OS to exercise its platform-specific cases. Some fixtures replace `PATH`
with test tools, so a script launcher should use an absolute interpreter path.
Both `./scripts/check` and the private `cli-nix` check run the full selection, including
the checkpoint cases, against an all-features build of the same source. `cli-nix` also
runs two smoke tests against the installed package.

The driver checks candidate behavior beyond command output.

- `version --json` names the launched file. Its `executablePath` and the supplied path
  must be the same file once both are canonicalized, so a launcher reports itself and not
  the interpreter or bundle it starts.
- The launched process owns the run, and its ownership ends when the process exits. The
  driver observes ownership only through `useful workflow run show RUN --json`, which
  reports `recovery.status` as `active` while a live process owns the run. The driver can
  end ownership by killing the launched process. A launcher must replace itself with the
  implementation so that the process the driver kills owns the run.
- `USEFUL_TEST_POLL_INTERVAL_MILLISECONDS` is an upper bound on the interval between a
  waiting command's polls of Cloud. The driver sets it on most commands. A build that
  ignores it reaches the same results at the production cadence, where about fifty cases
  take 5 s or more and two take over half of nextest's two-minute limit. The Rust CLI
  honors it in a build with `test-fixtures`, which `--all-features` enables.

The programs in `tests/native-free/` use only the Node 26 standard library to hold a run
and to start, stop and clean up a step's process group as this contract and the canonical
repository's `docs/product/workflow-execution.md` describe, and `./scripts/check` runs
them with `scripts/check-native-free-evidence`.

The driver sets `USEFUL_TEST_BINARY` to the supplied executable and unsets
`USEFUL_TEST_INTERNAL_WORKER_EXECUTABLE`. `USEFUL_TEST_ENVIRONMENT_WITNESS` is an
input to the driver's own fixtures only.

The reviewed command inventory is `tests/fixtures/command-tree.txt`. The driver probes
retired options on each path, including hidden commands. It executes the 13 design
scenarios in `tests/fixtures/command-scenarios.json` in a disposable signed-out checkout.
Stateful cases separately use the IDs, key files, artifacts and receipts earlier commands
produced.

Twenty-two additional cases use the checkpoint gates to order workflow processes or use
the hold seam to stand in for a live owner. Run them against a qualification build with
`scripts/test-e2e /absolute/path/to/useful --features candidate-checkpoints`. For Rust,
`scripts/test-e2e-rust` builds the qualification executable and runs the driver with the
checkpoint cases enabled. Pass nextest arguments to it to select a subset.

For a checkpoint gate, the driver supplies a path in one of the variables below. At the
named point the candidate creates an empty sibling file with the listed extension and
waits until the supplied path exists. A candidate that waits 30 s without seeing the path
fails the command.

| Variable | Extension | Point in the command |
| --- | --- | --- |
| `USEFUL_TEST_RUN_LOCK_GATE` | `.inspected` | After inspecting a run, before taking its lock |
| `USEFUL_TEST_CHILD_START_GATE` | `.starting` | Before preparing a stage's child |
| `USEFUL_TEST_SETTLED_GATE` | `.settled` | After execution settles, before the first read of withdrawals, in an attempt that is not a quiet child |
| `USEFUL_TEST_RELEASE_GATE` | `.releasing` | In an attempt that ends the run: under the controls lock, after spending withdrawals, before the final record |
| `USEFUL_TEST_BEGIN_GATE` | `.beginning` | Before a new attempt that does not continue an edge takes the controls lock to check for an outstanding withdrawal |

For the hold seam, the driver launches the candidate without arguments. It sets
`USEFUL_TEST_HOLD_RUNS` to run directories joined like entries in `PATH` and
`USEFUL_TEST_HOLD_RUNS_RELEASE` to a path with no extension. The candidate handles the
hold before parsing arguments. It keeps the default signal dispositions, takes ownership
of every named run as a command that continues the run would, and leaves the runs
unchanged. Once it owns them all, it creates an empty `<release>.held` file and waits
for the release path to exist. It exits 0 when released and exits 1 if it fails to take
ownership of a named run or if 30 s pass without release. The driver can also end the
hold by killing the candidate.

The process suite also exercises approval, upgrade, interruption and cancellation
through the supplied executable. The execution crate's own tests inspect the injected Rust TUI
lifecycle and the Linux guard's private registration handshake. PTY and process-lifecycle
tests cover their user-visible behavior in the executable suite.

From the platform root, the three pinned-harness scripts accept
`--cli /absolute/path/to/useful`. Run `scripts/pi-json-v1-conformance`,
`scripts/claude-code-stream-json-v1-conformance` and
`scripts/codex-app-server-v1-conformance` to qualify the candidate with the pinned
executables. The candidate tests drive Pi's mixed workflow and Codex and Claude
Code response exports with local provider fixtures. The default native gates also
exercise the implementation's internal adapters. Real-service runner and workflow
qualification adds Gateway and Coordinator interoperability evidence.

The workspace nextest run covers the crates' tests and `tests/architecture.rs` with the
checked-in `.config/nextest.toml` policy. It selects the locked workspace with all targets
and all features. The process suite runs only through the standalone driver. Nix runs
both suites and injects the package version and build identity into the build under test
and the driver's `USEFUL_TEST_VERSION` and `USEFUL_TEST_BUILD_IDENTITY`. The local suite
uses development defaults and reuses the binary from the process suite to package and
verify the release archive. The Nix package and release builds compile optimized binaries.
Clippy runs in the local suite and as the package's `clippy` and `e2eClippy` passthru
derivations, over the workspace and the standalone driver.

Nextest gives each selected test its own process, preventing a child forked by one test from
inheriting another test's open descriptors. This isolation does not prevent races among processes
created within one test, and it does not change production process behavior.

## Rust baseline upgrades

`package.rust-version` in `Cargo.toml` is the single Rust baseline declaration. Express
it as the selected stable `MAJOR.MINOR` release line. The development and MSRV
toolchains, production Nix package, and GitHub release builds derive their compiler from
that value; do not add a `rust-toolchain` file, a second version constant, or an older
compatibility build.

Advance the baseline directly when the project intentionally adopts a newer compiler or
dependency requirement. Before a bump, confirm that the release line is available from
the pinned Rust overlay and from rustup on every native release runner. Update
`Cargo.lock` only when the new baseline changes dependency resolution or when the same
change deliberately refreshes dependencies. Because the CLI is pre-release, replace the
old baseline rather than retaining parallel support.

Treat a higher source-build requirement as breaking release intent in the canonical
private journal. Validate a bump with `./scripts/check`, the monorepo dependency-state
check, and `nix flake check`; release CI builds every supported native target with the
candidate version.

## Release policy and archived notes

`release.toml` schema 2 is static policy, not mutable next-version intent. Keep its
initial version at `0.1.0`, development version at `0.0.0-dev`, and pre-1.0 breaking
impact at `minor`. Keep the Cargo fallback in `Cargo.toml` and `Cargo.lock` permanently
at `0.0.0-dev`. `./scripts/check-release` validates those values, and
`./scripts/release-impact` derives a version only when given explicit impact and an
optional latest stable version.

`changes/` is a frozen legacy archive. Do not add, modify, move, or delete fragments.
New release intent is admitted through the canonical private repository's append-only
journal and is intentionally absent from this exported source tree. Public notes still
describe present-tense user behavior and must not include credentials, private URLs,
customer or incident details, premature vulnerability details, or an `internal` marker
that conceals a user-visible security fix. Run `./scripts/check-change-fragments` to
validate the complete frozen archive offline.

Managed Buildkite advances public `main` to an untagged candidate after validating the
canonical source-evidence artifact. Public Actions verifies the candidate contract with
`scripts/verify-release-candidate`, checks Linux and macOS, and builds all three native
archives before the protected `cli-release` environment asks a human to approve the
proposed version and notes. The write-scoped `scripts/reconcile-release` publishes only a
candidate that is still public `main`, accepts matching absent, direct-tag, or draft state,
and leaves an exact published release unchanged. Run
`python3 scripts/test-release-candidate` for the local Git and mocked GitHub fixture. A
pre-tag failure is repaired by advancing `main` with a corrected candidate; do not reset
the branch, move a stable tag, edit a published release, or restore allocation and recovery
state.

## Security reports

Do not report vulnerabilities, credentials, or other sensitive details in a public
Discussion. Follow `SECURITY.md` instead.
