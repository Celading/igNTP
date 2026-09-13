# igNTP: operation

Prepare Cangjie/CJPM 1.1.3 and the declared dependency/platform assets. From the repository workspace, run `cjpm build -j1` and the actual emitted `igntp_test` binary; preserve its exit code. Run expensive or network tests with explicit timeouts.

Both the library and its core test project use only the Cangjie standard library.

For standalone use, follow the [README consumer example](../../README.md). A package-root build is different from a whole-workspace build. Never depend on another private checkout or silently skip failed tests.

Handle timeout, KoD, unsynchronized-server and transport errors. requestBest separates per-endpoint failures and may return no selected sample; do not treat an empty result as a synchronized clock.
