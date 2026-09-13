# igNTP - public API index

Package names below follow the library source declarations; `src` is a directory, not an import namespace.

## igntp


## igntp.Commons

- `ClockPort`
- `KissOfDeath`
- `LeapIndicator`
- `NtpConstants`
- `NtpErrorCode`
- `NtpException`
- `NtpMode`
- `NtpPacket`
- `NtpTimestamp`
- `igNTPBoundary`
- `igNTPScopeRuling`
- `isKissOfDeath`
- `isZero`
- `label`
- `referenceIdText`
- `toNtpEpochMillis`
- `toString`
- `toUnixEpochMillis`
- `value`

## igntp.Features


## igntp.Features.codec

- `NtpPacketCodec`

## igntp.Features.timesync

- `EndpointFailure`
- `EndpointSample`
- `MultiServerResult`
- `SyncResult`
- `TimeSync`
- `finish`
- `referenceIdText`
- `toString`

## igntp.Master

- `ExchangeBudget`
- `KodBackoff`
- `MonoClockPort`
- `NtpTransport`
- `SntpClient`
- `SystemClock`
- `SystemMonoClock`
- `UdpNtpTransport`
- `bind`
- `close`
- `expired`
- `isBound`
- `isOpen`
- `kodEndpointCount`
- `monoMs`
- `nowUnixMillis`
- `receiveFrom`
- `request`
- `requestBest`
- `sendTo`

## Typical entry point

See [recipes](../skill/recipes.md) for the README example and [verification](../skill/verify.md) to run the suite.
