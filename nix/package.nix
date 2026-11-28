{
  # Defaults to the hash part of the source fileset's store path, so the
  # identity changes with the CLI source and with nothing else.
  buildIdentity ? null,
  cacert,
  cargo-nextest,
  craneLib,
  darwin,
  git,
  jq,
  lib,
  # The CLI toolchain with Clippy. Only the passthru lint derivation uses it,
  # so the package, its dependency artifacts and its tests do not depend on it.
  lintCraneLib,
  python3,
  stdenv,
  version,
}:

let
  sourceFiles = [
    ../.config/nextest.toml
    ../Cargo.lock
    ../Cargo.toml
    ../crates
    ../docs/command-migration.md
    ../docs/workflow-v1.md
    ../examples
    ../schemas
    ../src
    ../tests
    ../vendor
  ];

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions sourceFiles;
  };

  # The grammar suite reads the output-style guide's verb lexicon;
  # the binary does not, so the guide joins only the test source and an edit to
  # it leaves the package and its build identity unchanged.
  testSrc = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions (sourceFiles ++ [ ../docs/output-style.md ]);
  };

  resolvedBuildIdentity =
    if buildIdentity != null then
      buildIdentity
    else
      builtins.head (
        lib.splitString "-" (baseNameOf (builtins.unsafeDiscardStringContext (toString src)))
      );

  commonArgs = {
    pname = "useful";
    inherit src;
    strictDeps = true;
  };

  # The dependency-only build is keyed on crate manifests and vendored sources. The
  # build identity changes with every CLI source change and must not reach this
  # derivation, or the cached dependency artifacts would be invalidated by
  # every source change.
  dependencyArgs = commonArgs // {
    version = "0.0.0-deps";
    # Keep the workspace's registry patch real when Crane stubs local crates.
    extraDummyScript = ''
      rm -rf "$out/vendor/rustls-platform-verifier"
      cp -R ${../vendor/rustls-platform-verifier} "$out/vendor/rustls-platform-verifier"
    '';
  };

  cargoArtifacts = craneLib.buildDepsOnly dependencyArgs;

  testProfileEnv = {
    CARGO_PROFILE_DEV_DEBUG = "0";
    CARGO_PROFILE_TEST_DEBUG = "0";
  };

  # Test and release dependency artifacts use different compiler profiles.
  # This input contains manifests and the patched vendor source. A workspace
  # source change always rebuilds the real test binaries and runs nextest.
  testCargoArtifacts = craneLib.buildDepsOnly (
    dependencyArgs
    // {
      pname = "useful-test";
      CARGO_PROFILE = "";
      env = testProfileEnv;
      buildPhaseCargoCommand = "cargo build --locked --workspace --all-targets --all-features";
      doCheck = false;
    }
  );

  certificateEnv = {
    SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";
  };

  # The test builds use fixed version and identity values. The process suite
  # checks those values on its candidate; the package's postInstall checks the
  # release binary's own version and identity.
  testVersion = "0.0.0-dev.0+rev.0000000000000000000000000000000000000000";
  testBuildIdentity = "0000000000000000000000000000000000000000";

  testArgs = commonArgs // {
    src = testSrc;
    version = testVersion;
    nativeBuildInputs = [
      git
      python3
    ]
    ++ lib.optionals stdenv.hostPlatform.isDarwin [ darwin.ps ];
    env = certificateEnv // {
      USEFUL_BUILD_IDENTITY = testBuildIdentity;
      USEFUL_VERSION = testVersion;
    };
  };

  # The workspace compiled once: every target with every feature, in Cargo's dev
  # and test profiles, over the test dependency artifacts. `nextestTests` runs
  # the suite from its artifacts without compiling again. Its `bin/useful` is
  # the `useful` bin target of this build, so the runner's, execution's and
  # support's `test-fixtures` features are compiled in; the Gateway's process
  # checks start it (a variable such as USEFUL_TEST_METADATA_CLEANUP_IDENTITY
  # changes it only when set). It needs only the compile, never a passing test.
  testBuild = craneLib.mkCargoDerivation (
    testArgs
    // {
      pname = "cli-test-build";
      # Crane defaults CARGO_PROFILE to release. The empty value passes no
      # --cargo-profile, so the tests are built in Cargo's test profile,
      # unoptimized with debug assertions and overflow checks, as check-suite
      # does.
      CARGO_PROFILE = "";
      cargoArtifacts = testCargoArtifacts;
      env = testArgs.env // testProfileEnv;
      # A plain build, unlike `cargo nextest run`, also compiles the ordinary
      # internal-worker example, which tests that spawn internal workers need.
      buildPhaseCargoCommand = "cargo build --locked --workspace --all-targets --all-features";
      doInstallCargoArtifacts = true;
      installPhaseCommand = ''
        mkdir -p "$out/bin"
        cp "''${CARGO_TARGET_DIR:-target}/debug/useful" "$out/bin/useful"
      '';
    }
  );

  # Run the workspace crate tests and the architecture test from the test build.
  nextestTests = craneLib.cargoNextest (
    testArgs
    // {
      cargoExtraArgs = "--locked --workspace --all-targets --all-features";
      CARGO_PROFILE = "";
      cargoArtifacts = testBuild;
      doInstallCargoArtifacts = false;
      env = testArgs.env // testProfileEnv;
      # Cargo leaves the workspace compiled: it compares sources with dep-info.
      preBuild = ''
        export USEFUL_TEST_INTERNAL_WORKER_EXECUTABLE="$(realpath "''${CARGO_TARGET_DIR:-target}/debug/examples/internal-worker")"
      '';
    }
  );
  # check-suite's lint gate over the test source and the Clippy configuration,
  # in Cargo's dev and test profiles as the suite runs it. Clippy checks the
  # dependencies in its own metadata-only mode, so it starts from the test
  # dependency artifacts, which already hold the build scripts and procedural
  # macros of that profile.
  clippy = lintCraneLib.cargoClippy (
    testArgs
    // {
      src = lib.fileset.toSource {
        root = ../.;
        fileset = lib.fileset.unions (
          sourceFiles
          ++ [
            ../clippy.toml
            ../docs/output-style.md
          ]
        );
      };
      cargoArtifacts = testCargoArtifacts;
      cargoExtraArgs = "--locked --workspace";
      cargoClippyExtraArgs = "--all-targets --all-features -- -D warnings";
      CARGO_PROFILE = "";
      doInstallCargoArtifacts = false;
      env = testArgs.env // testProfileEnv;
      installPhaseCommand = "mkdir -p $out";
    }
  );
  # A derivation over the test source that starts from the test dependency
  # artifacts in Cargo's test profile, as `nextestTests` does, for a check that
  # runs its own Cargo commands against the workspace and the process-suite
  # driver (`scripts/test-e2e`): both locks are vendored and nextest is on PATH.
  # `args` supplies at least `pname` and `buildPhaseCargoCommand`; its `env` and
  # `nativeBuildInputs` extend the test source's.
  mkTestDerivation =
    args:
    craneLib.mkCargoDerivation (
      testArgs
      // {
        src = lib.fileset.toSource {
          root = ../.;
          fileset = lib.fileset.unions (
            sourceFiles
            ++ [
              ../docs/output-style.md
              ../scripts/test-e2e
            ]
          );
        };
        cargoArtifacts = testCargoArtifacts;
        cargoVendorDir = craneLib.vendorMultipleCargoDeps {
          cargoLockList = [
            ../Cargo.lock
            ../tests/Cargo.lock
          ];
        };
        CARGO_PROFILE = "";
        doInstallCargoArtifacts = false;
        installPhaseCommand = "mkdir -p $out";
      }
      // args
      // {
        env = testArgs.env // testProfileEnv // (args.env or { });
        nativeBuildInputs =
          testArgs.nativeBuildInputs ++ [ cargo-nextest ] ++ (args.nativeBuildInputs or [ ]);
      }
    );
  # Build the driver against its own lock. Run the entire process suite against
  # the test build's `useful` and two smoke tests against the packaged release
  # binary.
  # Keep the implementation out of the driver's build sandbox. The executable
  # enters separately below, just as a rewrite candidate would.
  e2eSourceFiles = [
    ../tests
    ../scripts/test-e2e
    ../docs/command-migration.md
    ../docs/workflow-v1.md
    ../examples
    ../schemas
  ];
  e2eVendorDir = craneLib.vendorCargoDeps { cargoLock = ../tests/Cargo.lock; };
  e2eTests = craneLib.mkCargoDerivation {
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions e2eSourceFiles;
    };
    pname = "useful-e2e";
    inherit version;
    cargoArtifacts = null;
    cargoVendorDir = e2eVendorDir;
    nativeBuildInputs = [
      cargo-nextest
      git
      python3
    ];
    # The candidate builds its HTTP client before reading local runs.
    env =
      certificateEnv
      // testProfileEnv
      // {
        USEFUL_TEST_VERSION = testVersion;
        USEFUL_TEST_BUILD_IDENTITY = testBuildIdentity;
      };
    buildPhaseCargoCommand = ''
      bash scripts/test-e2e ${testBuild}/bin/useful --features candidate-checkpoints --no-fail-fast
      bash scripts/test-e2e ${package}/bin/useful \
        -E 'test(installed_command_tree_has_the_declared_paths_visibility_and_options) | test(validate_create_list_show_and_view_follow_the_same_local_run)'
    '';
    installPhaseCommand = "mkdir -p $out";
    doInstallCargoArtifacts = false;
  };

  # check-suite's lint gate over the standalone process-suite driver, which
  # builds against its own manifest and lock.
  e2eClippy = lintCraneLib.mkCargoDerivation {
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions (e2eSourceFiles ++ [ ../clippy.toml ]);
    };
    pname = "useful-e2e-clippy";
    inherit version;
    cargoArtifacts = null;
    cargoVendorDir = e2eVendorDir;
    env = testProfileEnv;
    buildPhaseCargoCommand = "cargo clippy --locked --manifest-path tests/Cargo.toml --all-targets --all-features -- -D warnings";
    installPhaseCommand = "mkdir -p $out";
    doInstallCargoArtifacts = false;
  };

  package = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts version;
      doCheck = false;

      nativeBuildInputs = [ jq ];

      env = certificateEnv // {
        USEFUL_BUILD_IDENTITY = resolvedBuildIdentity;
        USEFUL_VERSION = version;
      };

      passthru = {
        inherit
          cargoArtifacts
          clippy
          e2eClippy
          mkTestDerivation
          nextestTests
          testBuild
          testCargoArtifacts
          e2eTests
          ;
      };

      postInstall = ''
        expected="useful ${version}"
        for invocation in "version" "--version"; do
          actual="$($out/bin/useful "$invocation")"
          if [ "$actual" != "$expected" ]; then
            echo "unexpected version output for $invocation: $actual" >&2
            echo "expected: $expected" >&2
            exit 1
          fi
        done

        json="$($out/bin/useful version --json)"
        if ! printf '%s\n' "$json" | jq --exit-status \
          --arg buildIdentity ${lib.escapeShellArg resolvedBuildIdentity} \
          --arg executablePath "$out/bin/useful" \
          --arg version ${lib.escapeShellArg version} \
          '. == {
            "schemaVersion": 1,
            "command": "useful",
            "version": $version,
            "executablePath": $executablePath,
            "buildIdentity": $buildIdentity
          }' >/dev/null; then
          echo "unexpected JSON version output: $json" >&2
          exit 1
        fi
      '';

      meta = {
        description = "Command-line interface and runner for Useful Machinery";
        license = lib.licenses.asl20;
        mainProgram = "useful";
        platforms = lib.platforms.unix;
      };
    }
  );
in
package
