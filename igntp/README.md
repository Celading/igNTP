# igNTP — Preview

SNTP v4 unicast client and timestamp calculations for Cangjie applications.

## Current scope

Exact 48-byte packet encoding/decoding; NTP/Unix time conversion; offset and round-trip calculations; injectable clocks/transports; source endpoint and originate validation; bounded exchanges; per-endpoint Kiss-o'-Death backoff; sequential multi-server sampling and selection via requestBest.

Package name: `igntp`; package version: `0.1.0`. Preview describes the current supported scope, not completion of every future protocol feature.

## Requirements

Cangjie/CJPM 1.1.3 is the current verification toolchain on macOS arm64. Other platforms require their own validation. Prepare the SDK/runtime environment using the SDK instructions; do not commit local registry credentials or runtime binaries.

Both the library and its core test project use only the Cangjie standard library.

## Build and test

From the full source repository root:

```sh
cjpm build -j1
./target/release/bin/igntp_test
```

Execute the emitted test binary directly and retain its exit code. A failed dependency download is not a passing test. No shared workspace helper or pre-populated private cache is a documented prerequisite. To build just the library, run `cjpm build -j1` in its package directory.

## Independent use

These instructions use local source or an extracted source package; they do not claim a registry version is already publicly available. Put the library package (the directory containing its package `cjpm.toml`, not the outer workspace) beside a consumer. Add this to the consumer manifest, adapting only the relative path:

```toml
[dependencies]
igntp = { path = "../igntp" }
```

Use this as `src/main.cj` in an executable consumer:

```cangjie
package preview_example
import igntp.Features.timesync.*
main(): Int64 {
    let unixMillis: Int64 = 1700000000000
    let result = TimeSync.ntpToUnixMs(TimeSync.unixToNtpMs(unixMillis))
    println(result)
    if (result != unixMillis) { return 1 }
    return 0
}
```

Build with `cjpm build -j1` and run the emitted executable (`target/release/bin/main` for the verified standalone layout). Expected output:

```text
1700000000000
```

## Error handling

Handle timeout, KoD, unsynchronized-server and transport errors. requestBest separates per-endpoint failures and may return no selected sample; do not treat an empty result as a synchronized clock.

## Resource and trust boundaries

The client reports time estimates and never changes the system clock. Every exchange has a monotonic budget. KoD backoff is keyed by host/resolved endpoint and bounded to 64 records. Invalid datagrams are discarded within the same budget; this is not unlimited waiting. Multi-server selection uses stratum, root delay and RTT, and reports failures separately.

## Limitations

No NTS/MAC authentication, clock discipline daemon, server/broadcast/symmetric role or automatic retransmission. Public-network availability is external and live tests are opt-in. A server receive timestamp of zero can make calculated delay unreliable; callers must apply an appropriate quality policy.

## Standards and licensing

RFC 4330 is the recorded SNTP reference. Multi-server selection is an application policy, not an implementation of the complete NTP clock-discipline algorithms.

Independent implementation; no affiliation or standards certification is implied. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
