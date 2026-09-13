package igntp_test

import igntp.Commons.*
import igntp.Features.codec.*
import igntp.Features.timesync.*
import igntp.Master.*
import std.collection.*
import std.env.*
import std.time.*

/// Deterministic monotonic clock: each read advances by stepMs.
class FakeMonoClock <: MonoClockPort {
    private var now: Int64
    private let stepMs: Int64

    public init(startMs!: Int64 = 0, stepMs!: Int64 = 1000) {
        this.now = startMs
        this.stepMs = stepMs
    }

    public func monoMs(): Int64 {
        let v = now
        now += stepMs
        v
    }
}

/// igNTP canonical test front door (fail-closed).
/// Run: cd igntp_test && cjpm run
/// Exit 0 = all checks pass; exit 1 = any failure.

var passCount: Int64 = 0
var failCount: Int64 = 0

func check(name: String, ok: Bool): Unit {
    if (ok) {
        passCount++
        println("  PASS: ${name}")
    } else {
        failCount++
        println("  FAIL: ${name}")
    }
}

func bytesEqual(a: Array<Byte>, b: Array<Byte>): Bool {
    if (a.size != b.size) {
        return false
    }
    for (i in 0..a.size) {
        if (a[i] != b[i]) {
            return false
        }
    }
    true
}

func throwsNtp(fn: () -> Unit): Bool {
    try {
        fn()
        false
    } catch (_: NtpException) {
        true
    } catch (_: Exception) {
        false
    }
}

/// Scriptable datagram transport.
class ScriptableNtpTransport <: NtpTransport {
    public var sent: ArrayList<Array<Byte>>
    public var script: ArrayList<Array<Byte>>
    public var bound: Bool
    public var closed: Bool
    /// Source address reported to receiveFrom callers (F2 tests).
    public var sourceHost: String
    public var sourcePort: UInt16

    public init() {
        this.sent = ArrayList<Array<Byte>>()
        this.script = ArrayList<Array<Byte>>()
        this.bound = false
        this.closed = false
        this.sourceHost = "test-host"
        this.sourcePort = 123
    }

    public func feed(datagram: Array<Byte>): Unit {
        script.add(datagram)
    }

    public func bind(port: UInt16): Unit {
        bound = true
    }

    public func sendTo(host: String, port: UInt16, data: Array<Byte>): Unit {
        sent.add(data)
    }

    public func receiveFrom(buf: Array<Byte>): (Int64, String, UInt16) {
        if (script.size == 0) {
            return (0, "", 0)
        }
        let datagram = script[0]
        script.remove(0..1)
        var count: Int64 = 0
        while (count < datagram.size && count < buf.size) {
            buf[count] = datagram[count]
            count++
        }
        (count, sourceHost, sourcePort)
    }

    public func close(): Unit {
        closed = true
    }

    public func isOpen(): Bool {
        bound && !closed
    }
}

/// Deterministic clock: returns scripted readings in order, holding the
/// last one. request() reads it twice (transmit build, deadline) plus
/// once for destination after the response.
class FakeClock <: ClockPort {
    private let readings: Array<Int64>
    private var index: Int64
    /// After scripted readings are exhausted, each read advances the held
    /// value by this step (deterministic termination for budget tests).
    public var autoAdvanceMs: Int64 = 0

    public init(readings!: Array<Int64>) {
        this.readings = readings
        this.index = 0
    }

    public func nowUnixMillis(): Int64 {
        var v = readings[index]
        if (index < readings.size - 1) {
            index++
        } else if (autoAdvanceMs > 0) {
            v = readings[readings.size - 1] + autoAdvanceMs
            readings[readings.size - 1] = v
        }
        v
    }
}

// ---- fixture helpers (hand-computed) ----

/// Valid server response (GPS primary, stratum 2):
///   24 02 06 FA 00000100 00000200 47505300
///   83AA7E80 40000000  (reference)
///   83AA7E80 00000000  (originate — echoes request transmit)
///   83AA7E81 00000000  (receive)
///   83AA7E81 40000000  (transmit)
func validResponseBytes(): Array<Byte> {
    [
        UInt8(0x24), UInt8(0x02), UInt8(0x06), UInt8(0xFA),
        UInt8(0x00), UInt8(0x00), UInt8(0x01), UInt8(0x00),
        UInt8(0x00), UInt8(0x00), UInt8(0x02), UInt8(0x00),
        UInt8(0x47), UInt8(0x50), UInt8(0x53), UInt8(0x00), // "GPS\0"
        UInt8(0x83), UInt8(0xAA), UInt8(0x7E), UInt8(0x80),
        UInt8(0x40), UInt8(0x00), UInt8(0x00), UInt8(0x00),
        UInt8(0x83), UInt8(0xAA), UInt8(0x7E), UInt8(0x80),
        UInt8(0x00), UInt8(0x00), UInt8(0x00), UInt8(0x00),
        UInt8(0x83), UInt8(0xAA), UInt8(0x7E), UInt8(0x81),
        UInt8(0x00), UInt8(0x00), UInt8(0x00), UInt8(0x00),
        UInt8(0x83), UInt8(0xAA), UInt8(0x7E), UInt8(0x81),
        UInt8(0x40), UInt8(0x00), UInt8(0x00), UInt8(0x00)
    ]
}

/// KoD (RFC 4330 §8): LI=3, stratum 0, refid "RATE":
///   E4 00 06 FA 00000100 00000200 52415454 + echoed originate
/// KoD datagram whose originate timestamp echoes `originate` (the
/// client's transmit), so the client's anti-replay check passes and the
/// KoD classification is reached.
func kodBytesEchoing(originate: NtpTimestamp): Array<Byte> {
    var out = kodBytes()
    // originate lives at bytes 24..32 (seconds 24..28, fraction 28..32).
    out[24] = UInt8((originate.seconds >> 24) & 0xFF)
    out[25] = UInt8((originate.seconds >> 16) & 0xFF)
    out[26] = UInt8((originate.seconds >> 8) & 0xFF)
    out[27] = UInt8(originate.seconds & 0xFF)
    out[28] = UInt8((originate.fraction >> 24) & 0xFF)
    out[29] = UInt8((originate.fraction >> 16) & 0xFF)
    out[30] = UInt8((originate.fraction >> 8) & 0xFF)
    out[31] = UInt8(originate.fraction & 0xFF)
    out
}

func kodBytes(): Array<Byte> {
    var out = Array<Byte>(48, repeat: 0)
    out[0] = UInt8(0xE4)
    out[1] = UInt8(0x00)
    out[12] = UInt8(0x52) // R
    out[13] = UInt8(0x41) // A
    out[14] = UInt8(0x54) // T
    out[15] = UInt8(0x45) // E
    // KoD still echoes the client's transmit timestamp in originate.
    out[24] = UInt8(0x83)
    out[25] = UInt8(0xAA)
    out[26] = UInt8(0x7E)
    out[27] = UInt8(0x80)
    out
}

// ---- epoch conversion + fraction precision ----

func testEpochConversion(): Bool {
    // Unix 0 == NTP 2208988800s.
    if (TimeSync.unixToNtpMs(0) != 2208988800000) {
        return false
    }
    if (TimeSync.ntpToUnixMs(2208988800000) != 0) {
        return false
    }
    // Fraction 0x80000000 == exactly 0.5 s == 500 ms.
    let half = NtpTimestamp(seconds: 0, fraction: 0x80000000)
    if (half.toNtpEpochMillis() != 500) {
        return false
    }
    // Fraction 0x40000000 == 0.25 s == 250 ms.
    let quarter = NtpTimestamp(seconds: 0, fraction: 0x40000000)
    quarter.toNtpEpochMillis() == 250
}

func testTimestampFromUnixMillis(): Bool {
    // Unix 0 → NTP seconds 0x83AA7E80, fraction 0.
    let ts = TimeSync.timestampFromUnixMillis(0)
    var ok = ts.seconds == 0x83AA7E80 && ts.fraction == 0
    // Unix 1250 → NTP 2208988801.25 s → fraction 0x40000000.
    let ts2 = TimeSync.timestampFromUnixMillis(1250)
    ok = ok && ts2.seconds == 0x83AA7E81 && ts2.fraction == 0x40000000
    ok
}

// ---- on-wire offset/delay math ----

func testOffsetDelayMath(): Bool {
    // t1=...800.0, t2=...801.0, t3=...801.25, t4=...801.25 (client slow)
    let t1 = NtpTimestamp(seconds: 0x83AA7E80, fraction: 0)
    let t2 = NtpTimestamp(seconds: 0x83AA7E81, fraction: 0)
    let t3 = NtpTimestamp(seconds: 0x83AA7E81, fraction: 0x40000000)
    let t4 = NtpTimestamp(seconds: 0x83AA7E81, fraction: 0x40000000)
    // offset = ((1000) + (0))/2 = 500 ms; delay = (1250) - (250) = 1000 ms
    TimeSync.offsetMillis(t1, t2, t3, t4) == 500 &&
        TimeSync.delayMillis(t1, t2, t3, t4) == 1000
}

// ---- request fixture (hand-computed) ----

func testRequestFixture(): Bool {
    let packet = NtpPacket(
        leapIndicator: LeapIndicator.NoWarning,
        version: 4,
        mode: NtpMode.Client,
        stratum: 0,
        transmitTimestamp: NtpTimestamp(seconds: 0x83AA7E80, fraction: 0))
    let wire = NtpPacketCodec.encode(packet)
    if (wire.size != 48) {
        return false
    }
    if (wire[0] != UInt8(0x23)) { // LI=0 VN=4 Mode=3
        return false
    }
    for (i in 1..40) {
        if (wire[i] != UInt8(0)) {
            return false
        }
    }
    wire[40] == UInt8(0x83) && wire[41] == UInt8(0xAA) &&
        wire[42] == UInt8(0x7E) && wire[43] == UInt8(0x80) &&
        bytesEqual(wire, NtpPacketCodec.encode(NtpPacketCodec.decode(wire)))
}

// ---- response fixture + field parsing ----

func testResponseParse(): Bool {
    let response = NtpPacketCodec.decode(validResponseBytes())
    response.mode == NtpMode.Server && response.version == 4 &&
        response.leapIndicator == LeapIndicator.NoWarning &&
        response.stratum == 2 && response.poll == 6 && response.precision == -6 &&
        response.rootDelay == 0x100 && response.rootDispersion == 0x200 &&
        response.referenceIdText() == "GPS\\x00" &&
        response.receiveTimestamp.seconds == 0x83AA7E81
}

// ---- client exchange (scripted transport + fake clock) ----

/// FakeClock readings (regression: the entry gate reads the monotonic clock,
/// so wall is read only for transmit and destination):
///   [0 (transmit), 1250 (destination)].
/// Expected: offset=+500ms, rtt=1000ms, serverTimeUnixMs=1250.
func testClientSuccessfulExchange(): Bool {
    let t = ScriptableNtpTransport()
    t.feed(validResponseBytes())
    let clock = FakeClock(readings: [0, 1250])
    let client = SntpClient(transport: t, clock: clock)
    client.bind(0)
    let result = client.request(host: "test-host")
    var ok = result.offsetMs == 500 && result.rttMs == 1000
    ok = ok && result.serverTimeUnixMs == 1250
    ok = ok && result.stratum == 2
    // The request on the wire must be a 48-byte client-mode packet.
    ok = ok && t.sent.size == 1 && t.sent[0].size == 48 && t.sent[0][0] == UInt8(0x23)
    ok
}

// ---- validation state machine ----

func testAntiReplayRejectsNonEchoedOriginate(): Bool {
    // regression: the replayed datagram is DISCARDED and the
    // exchange continues — the valid response that follows wins.
    let bytes = validResponseBytes()
    bytes[31] = UInt8(0x01) // corrupt originate fraction LSB
    let good = validResponseBytes()
    let t = ScriptableNtpTransport()
    t.feed(bytes)
    t.feed(good)
    let clock = FakeClock(readings: [0, 1250])
    let client = SntpClient(transport: t, clock: clock, timeoutMs: 500)
    client.bind(0)
    var ok = false
    try {
        let r = client.request(host: "test-host")
        ok = r.stratum == 2
    } catch (_: Exception) {
        ok = false
    }
    ok
}

func testKissOfDeathSurfacesCode(): Bool {
    let t = ScriptableNtpTransport()
    t.feed(kodBytes())
    let clock = FakeClock(readings: [0, 0, 1250, 1250])
    let client = SntpClient(transport: t, clock: clock)
    client.bind(0)
    var kod = false
    try {
        client.request(host: "test-host")
    } catch (e: NtpException) {
        kod = e.code == NtpErrorCode.KissOfDeathReceived &&
            e.message.contains("RATE")
    } catch (_: Exception) {
        kod = false
    }
    kod
}

func testUnsynchronizedRejected(): Bool {
    // LI=3 with stratum 2 (not KoD — plain unsynchronized server).
    let bytes = validResponseBytes()
    bytes[0] = UInt8(0xE4) // LI=3, VN=4, Mode=4
    let t = ScriptableNtpTransport()
    t.feed(bytes)
    let clock = FakeClock(readings: [0, 0, 1250, 1250])
    let client = SntpClient(transport: t, clock: clock)
    client.bind(0)
    var rejected = false
    try {
        client.request(host: "test-host")
    } catch (e: NtpException) {
        rejected = e.code == NtpErrorCode.Unsynchronized
    } catch (_: Exception) {
        rejected = false
    }
    rejected
}

func testVersionMismatchRejected(): Bool {
    // regression: wrong-version datagrams are discarded.
    let bytes = validResponseBytes()
    bytes[0] = UInt8(0x1C) // LI=0 VN=3 Mode=4
    let good = validResponseBytes()
    let t = ScriptableNtpTransport()
    t.feed(bytes)
    t.feed(good)
    let clock = FakeClock(readings: [0, 1250])
    let client = SntpClient(transport: t, clock: clock, timeoutMs: 500)
    client.bind(0)
    var ok = false
    try {
        let r = client.request(host: "test-host")
        ok = r.stratum == 2
    } catch (_: Exception) {
        ok = false
    }
    ok
}

func testModeMismatchRejected(): Bool {
    // Server replied with mode=client (0x23) — a reflection, not a server.
    // regression: mode-reflection datagrams are discarded.
    let bytes = validResponseBytes()
    bytes[0] = UInt8(0x23)
    let good = validResponseBytes()
    let t = ScriptableNtpTransport()
    t.feed(bytes)
    t.feed(good)
    let clock = FakeClock(readings: [0, 1250])
    let client = SntpClient(transport: t, clock: clock, timeoutMs: 500)
    client.bind(0)
    var ok = false
    try {
        let r = client.request(host: "test-host")
        ok = r.stratum == 2
    } catch (_: Exception) {
        ok = false
    }
    ok
}

func testShortDatagramRejected(): Bool {
    let bytes = validResponseBytes()
    let short = bytes[0..47]
    var rejected = false
    try {
        NtpPacketCodec.decode(short)
    } catch (e: NtpException) {
        rejected = e.code == NtpErrorCode.DecodeError
    } catch (_: Exception) {
        rejected = false
    }
    rejected
}

func testClosedTransportFailsFast(): Bool {
    let t = ScriptableNtpTransport()
    let clock = FakeClock(readings: [0, 0, 1250, 1250])
    let client = SntpClient(transport: t, clock: clock)
    client.bind(0)
    client.close()
    var failed = false
    try {
        client.request(host: "test-host")
    } catch (e: NtpException) {
        failed = e.code == NtpErrorCode.ConnectionClosed
    } catch (_: Exception) {
        failed = false
    }
    failed
}

// ---- regression regression tests ----

/// F2 regression: a valid response from a non-target source address must
/// be dropped (exchange times out), never accepted.
func testSpoofedSourceDropped(): Bool {
    let t = ScriptableNtpTransport()
    t.sourceHost = "evil-host"
    t.feed(validResponseBytes())
    // clock readings: gate=0, transmit=0, deadline=1250, then 9000 —
    // the poll loop would never expire against a real deadline, so use
    // readings that advance past the deadline: deadline=1250+5000=6250,
    // subsequent reads return 9000 (>= deadline).
    let clock = FakeClock(readings: [0, 0, 1250, 9000, 9000, 9000, 9000, 9000, 9000, 9000, 9000])
    let client = SntpClient(transport: t, clock: clock)
    client.bind(0)
    var timedOut = false
    try {
        client.request(host: "test-host")
    } catch (e: NtpException) {
        timedOut = e.code == NtpErrorCode.Timeout
    } catch (_: Exception) {
        timedOut = false
    }
    timedOut
}

/// F2 positive: the same valid response from the expected source is
/// accepted (source set contains the literal host string).
func testExpectedSourceAccepted(): Bool {
    let t = ScriptableNtpTransport()
    t.sourceHost = "test-host"
    t.feed(validResponseBytes())
    let clock = FakeClock(readings: [0, 1250])
    let client = SntpClient(transport: t, clock: clock)
    client.bind(0)
    var ok = false
    try {
        let result = client.request(host: "test-host")
        ok = result.offsetMs == 500
    } catch (_: Exception) {
        ok = false
    }
    ok
}

func testWrongSourcePortDropped(): Bool {
    let t = ScriptableNtpTransport()
    t.sourcePort = 9999
    t.feed(validResponseBytes())
    let clock = FakeClock(readings: [0, 0, 1250, 9000, 9000, 9000])
    let client = SntpClient(transport: t, clock: clock)
    client.bind(0)
    var timedOut = false
    try {
        client.request(host: "test-host")
    } catch (e: NtpException) {
        timedOut = e.code == NtpErrorCode.Timeout
    } catch (_: Exception) {
        timedOut = false
    }
    timedOut
}

/// F1 regression: after KoD, an immediate retry must NOT touch the wire
/// (backoff), and must still surface KissOfDeathReceived.
func testKodBackoffBlocksImmediateRetry(): Bool {
    let t = ScriptableNtpTransport()
    t.feed(kodBytes())
    // readings: request1 = [0 (gate), 0 (transmit), 1250 (deadline)];
    // request2 entry = [1250 (backoff check, < backoff window)]; after
    // backoff expiry the check reads 2000 and the exchange times out.
    let clock = FakeClock(readings: [0, 0, 1250, 1250, 1250])
    let client = SntpClient(transport: t, clock: clock, kodBackoffMs: 50)
    client.bind(0)

    var firstKod = false
    try {
        client.request(host: "test-host")
    } catch (e: NtpException) {
        firstKod = e.code == NtpErrorCode.KissOfDeathReceived
    } catch (_: Exception) {
        firstKod = false
    }

    // Immediate retry: no wire traffic allowed during backoff.
    var secondKod = false
    try {
        client.request(host: "test-host")
    } catch (e: NtpException) {
        secondKod = e.code == NtpErrorCode.KissOfDeathReceived
    } catch (_: Exception) {
        secondKod = false
    }

    firstKod && secondKod && t.sent.size == 1
}

/// F1: after the backoff window expires (monotonic clock advanced), the
/// request goes back on the wire. regression R4: the backoff deadline now
/// lives on the MONOTONIC base — FakeMonoClock steps 1000ms per read,
/// so the 50ms window is well past once request1's mono reads (budget
/// start, KoD store) have advanced it, and request2 proceeds to the
/// wire and times out on the empty script.
func testKodBackoffExpires(): Bool {
    let t = ScriptableNtpTransport()
    t.feed(kodBytes())
    // Wall readings are only used for transmit/destination now; the
    // backoff gate and budget both read the injected FakeMonoClock.
    let clock = FakeClock(readings: [0, 0, 1250, 1250])
    clock.autoAdvanceMs = 3000
    let mono = FakeMonoClock(startMs: 0, stepMs: 1000)
    let client = SntpClient(transport: t, clock: clock, monoClock: mono,
                            timeoutMs: 5000, kodBackoffMs: 50)
    client.bind(0)
    var firstKod = false
    try {
        client.request(host: "test-host")
    } catch (e: NtpException) {
        firstKod = e.code == NtpErrorCode.KissOfDeathReceived
    } catch (_: Exception) {
        firstKod = false
    }
    var secondTimedOut = false
    try {
        client.request(host: "test-host")
    } catch (e: NtpException) {
        secondTimedOut = e.code == NtpErrorCode.Timeout
    } catch (_: Exception) {
        secondTimedOut = false
    }
    firstKod && secondTimedOut && t.sent.size == 2
}

/// F3 regression: zero transmit timestamp -> ProtocolViolation.
func testZeroTransmitResponseRejected(): Bool {
    // regression: zero-transmit datagrams are discarded.
    let bytes = validResponseBytes()
    for (i in 40..48) {
        bytes[i] = UInt8(0)
    }
    let good = validResponseBytes()
    let t = ScriptableNtpTransport()
    t.feed(bytes)
    t.feed(good)
    let clock = FakeClock(readings: [0, 1250])
    let client = SntpClient(transport: t, clock: clock, timeoutMs: 500)
    client.bind(0)
    var ok = false
    try {
        let r = client.request(host: "test-host")
        ok = r.stratum == 2
    } catch (_: Exception) {
        ok = false
    }
    ok
}

/// F4 regression: offset uses floor (arithmetic shift), not truncation.
/// Construct a -1 ms sum: t2 trails t1 by exactly one second MINUS the
/// ms representable by fraction 4290774223 (≈ 999 ms), so t2-t1 = -1 ms
/// while t3-t4 = 0. floor(-1/2) = -1; truncation would give 0 — the two
/// rounding rules differ, making this a discriminating check.
func testNegativeOffsetFloorRounding(): Bool {
    let e1 = NtpTimestamp(seconds: 100, fraction: 0)
    let e2 = NtpTimestamp(seconds: 99, fraction: 4290774223)
    let e3 = NtpTimestamp(seconds: 100, fraction: 0)
    let e4 = NtpTimestamp(seconds: 100, fraction: 0)
    // Guard: confirm the fixture really encodes a -1 ms difference.
    let a = e2.toNtpEpochMillis() - e1.toNtpEpochMillis()
    if (a != -1) {
        return false
    }
    TimeSync.offsetMillis(e1, e2, e3, e4) == -1
}

/// F5 regression: pre-era times are rejected.
func testPreEraTimestampRejected(): Bool {
    throwsNtp({ => TimeSync.timestampFromUnixMillis(-2208988800001) })
}

// ---- regression RED tests (fail against wall-budget / global KoD) ----

/// D2 green: the monotonic budget expires on monotonic elapsed alone —
/// a wall step backward (wall reading below both start and deadline)
/// cannot un-expire it. Budget: monoStart 3000, window 5000, mono now
/// 9000 → elapsed 6000 ≥ 5000 → expired.
func testBudgetExpiresDespiteWallStepBackward(): Bool {
    let budget = ExchangeBudget(monoStartMs: 3000, timeoutMs: 5000)
    budget.expired(9000)
}

/// D1 red: a KoD from endpoint A must not block a request to endpoint B.
/// The transport records every datagram; after the KoD from A, a request
/// to B must still REACH THE WIRE (global backoff threw at entry with
/// zero sends to B — the cross-endpoint defect).
func testKodBackoffIsPerEndpoint(): Bool {
    let t = ScriptableNtpTransport()
    let clock = FakeClock(readings: [0])
    let client = SntpClient(transport: t, clock: clock, kodBackoffMs: 60000)
    client.bind(0)

    // 1. KoD from endpoint A. The client's transmit (wall 0ms → NTP
    // 2208988800.0) must be echoed in originate, or the anti-replay
    // check rejects before the KoD classification is reached.
    t.sourceHost = "server-a"
    let transmitTs = TimeSync.timestampFromUnixMillis(0)
    t.feed(kodBytesEchoing(transmitTs))
    var firstKod = false
    var firstCode: Int64 = -1
    try {
        client.request(host: "server-a")
    } catch (e: NtpException) {
        firstCode = e.code
        firstKod = e.code == NtpErrorCode.KissOfDeathReceived
    } catch (_: Exception) {
        firstKod = false
    }
    if (!firstKod) { return false }
    let sendsAfterKod = t.sent.size

    // 2. Request to endpoint B — must reach the wire despite A's backoff.
    // B never answers, so the honest outcome is Timeout (NOT KoD — the
    // cross-endpoint defect threw KoD at entry without any datagram).
    var timedOutOnB = false
    var kodOnB = false
    try {
        client.request(host: "server-b")
    } catch (e: NtpException) {
        kodOnB = e.code == NtpErrorCode.KissOfDeathReceived
        timedOutOnB = e.code == NtpErrorCode.Timeout
    } catch (_: Exception) {
        timedOutOnB = false
    }
    // Wire carried: 1 datagram to A + at least 1 to B.
    timedOutOnB && !kodOnB && t.sent.size >= sendsAfterKod + 1
}

// ---- regression RED tests (fail against loop-starving budget / split KoD keys) ----

/// Transport whose receiveFrom ALWAYS returns a valid-shaped datagram
/// from a wrong source — a true continuous flood, unlike the finite
/// 10-packet script. A harness guard bounds the run so a starved
/// budget fails the check instead of hanging the binary.
class FloodWrongSourceTransport <: NtpTransport {
    public var receives: Int64 = 0
    public var sent: ArrayList<Array<Byte>> = ArrayList<Array<Byte>>()
    private var bound: Bool = false
    private var closed: Bool = false
    private let guardLimit: Int64

    public init(guardLimit!: Int64 = 100000) {
        this.guardLimit = guardLimit
    }

    public func bind(port: UInt16): Unit {
        bound = true
    }

    public func sendTo(host: String, port: UInt16, data: Array<Byte>): Unit {
        sent.add(data)
    }

    public func receiveFrom(buf: Array<Byte>): (Int64, String, UInt16) {
        receives++
        if (receives > guardLimit) {
            throw NtpException(
                code: NtpErrorCode.ConnectionClosed,
                message: "harness flood guard tripped (budget never gated the loop)")
        }
        let wire = validResponseBytes()
        var count: Int64 = 0
        while (count < wire.size && count < buf.size) {
            buf[count] = wire[count]
            count++
        }
        (count, "evil-host", 123)
    }

    public func close(): Unit {
        closed = true
    }

    public func isOpen(): Bool {
        bound && !closed
    }
}

/// regression R1: with wrong-source datagrams arriving CONTINUOUSLY, the total
/// budget must gate every receive and the exchange must end in Timeout
/// within a handful of loop iterations — never spin to the harness
/// guard. The old code checked the budget only on the empty-read path,
/// so the wrong-source `continue` skipped it forever.
func testContinuousWrongSourceFloodTerminates(): Bool {
    let t = FloodWrongSourceTransport()
    let clock = FakeClock(readings: [0, 0])
    let mono = FakeMonoClock(startMs: 0, stepMs: 1000)
    let client = SntpClient(transport: t, clock: clock, monoClock: mono, timeoutMs: 5000)
    client.bind(0)
    var timedOut = false
    try {
        client.request(host: "test-host")
    } catch (e: NtpException) {
        timedOut = e.code == NtpErrorCode.Timeout
    } catch (_: Exception) {
        timedOut = false
    }
    timedOut && t.receives < 1000
}

/// regression R3: a KoD arriving from the RESOLVED address of a hostname must
/// stop re-sends addressed by that hostname ("localhost" resolves to
/// 127.0.0.1 hermetically). The old code stored backoff under the
/// source IP key only, so a hostname retry missed it and went back on
/// the wire — the exact DNS-name/IP-response gap.
func testKodFromResolvedIpBlocksHostnameRetry(): Bool {
    let t = ScriptableNtpTransport()
    t.sourceHost = "127.0.0.1"
    t.feed(kodBytesEchoing(TimeSync.timestampFromUnixMillis(0)))
    let clock = FakeClock(readings: [0])
    let mono = FakeMonoClock(startMs: 0, stepMs: 1000)
    let client = SntpClient(transport: t, clock: clock, monoClock: mono, kodBackoffMs: 60000)
    client.bind(0)
    var firstKod = false
    try {
        client.request(host: "localhost")
    } catch (e: NtpException) {
        firstKod = e.code == NtpErrorCode.KissOfDeathReceived
    } catch (_: Exception) {
        firstKod = false
    }
    if (!firstKod) {
        return false
    }
    var secondBlockedAtEntry = false
    try {
        client.request(host: "localhost")
    } catch (e: NtpException) {
        secondBlockedAtEntry = e.code == NtpErrorCode.KissOfDeathReceived
    } catch (_: Exception) {
        secondBlockedAtEntry = false
    }
    secondBlockedAtEntry && t.sent.size == 1
}

/// regression R3 isolation guard: the KoD backoff above must NOT leak into the
/// same host on a different port, nor into a different host. Both
/// requests must reach the wire and time out.
func testKodBackoffIsolatedAcrossPortsAndHosts(): Bool {
    let t = ScriptableNtpTransport()
    t.sourceHost = "127.0.0.1"
    t.feed(kodBytesEchoing(TimeSync.timestampFromUnixMillis(0)))
    let clock = FakeClock(readings: [0])
    let mono = FakeMonoClock(startMs: 0, stepMs: 1000)
    let client = SntpClient(transport: t, clock: clock, monoClock: mono, kodBackoffMs: 60000)
    client.bind(0)
    var firstKod = false
    try {
        client.request(host: "localhost")
    } catch (e: NtpException) {
        firstKod = e.code == NtpErrorCode.KissOfDeathReceived
    } catch (_: Exception) {
        firstKod = false
    }
    if (!firstKod) {
        return false
    }
    var port124TimedOut = false
    try {
        client.request(host: "localhost", port: 124)
    } catch (e: NtpException) {
        port124TimedOut = e.code == NtpErrorCode.Timeout
    } catch (_: Exception) {
        port124TimedOut = false
    }
    var otherHostTimedOut = false
    try {
        client.request(host: "server-b")
    } catch (e: NtpException) {
        otherHostTimedOut = e.code == NtpErrorCode.Timeout
    } catch (_: Exception) {
        otherHostTimedOut = false
    }
    port124TimedOut && otherHostTimedOut && t.sent.size == 3
}

/// regression R4: the KoD backoff map is capacity-bounded — 70 distinct KoD'd
/// endpoints must leave at most 64 keys stored (sweep + soonest-expiring
/// eviction). Failing-before evidence is the API absence itself: the old
/// client kept two unbounded maps with no eviction and no introspection.
func testKodBackoffMapBounded(): Bool {
    let t = ScriptableNtpTransport()
    let clock = FakeClock(readings: [0])
    let mono = FakeMonoClock(startMs: 0, stepMs: 1000)
    let client = SntpClient(transport: t, clock: clock, monoClock: mono, kodBackoffMs: 60000)
    client.bind(0)
    let transmitTs = TimeSync.timestampFromUnixMillis(0)
    var i: Int64 = 0
    while (i < 70) {
        t.sourceHost = "srv-${i}"
        t.feed(kodBytesEchoing(transmitTs))
        var kod = false
        try {
            client.request(host: "srv-${i}")
        } catch (e: NtpException) {
            kod = e.code == NtpErrorCode.KissOfDeathReceived
        } catch (_: Exception) {
            kod = false
        }
        if (!kod) {
            return false
        }
        i++
    }
    client.kodEndpointCount() <= 64
}

/// Per-endpoint scripted transport for multi-server tests: replies are
/// registered per (host, port) and claimed when sendTo addresses them.
/// An endpoint without a reply simply times out.
class MultiEndpointTransport <: NtpTransport {
    public var pending: ArrayList<(String, UInt16, Array<Byte>)>
    public var rx: ArrayList<(String, UInt16, Array<Byte>)>
    public var bound: Bool
    public var closed: Bool

    public init() {
        this.pending = ArrayList<(String, UInt16, Array<Byte>)>()
        this.rx = ArrayList<(String, UInt16, Array<Byte>)>()
        this.bound = false
        this.closed = false
    }

    public func reply(host: String, port: UInt16, datagram: Array<Byte>): Unit {
        pending.add((host, port, datagram))
    }

    public func bind(port: UInt16): Unit {
        bound = true
    }

    public func sendTo(host: String, port: UInt16, data: Array<Byte>): Unit {
        for (i in 0..pending.size) {
            let (h, p, d) = pending[i]
            if (h == host && p == port) {
                pending.remove(i..i + 1)
                rx.add((h, p, d))
                return
            }
        }
    }

    public func receiveFrom(buf: Array<Byte>): (Int64, String, UInt16) {
        if (rx.size == 0) {
            return (0, "", 0)
        }
        let (h, p, d) = rx[0]
        rx.remove(0..1)
        var count: Int64 = 0
        while (count < d.size && count < buf.size) {
            buf[count] = d[count]
            count++
        }
        (count, h, p)
    }

    public func close(): Unit {
        closed = true
    }

    public func isOpen(): Bool {
        bound && !closed
    }
}

/// Server response with configurable stratum, root delay (16.16 raw),
/// and an originate echo of `originate`; receive/transmit are shifted
/// forward by shiftMs (NTP-epoch ms) from the originate value.
func multiResponse(originate: NtpTimestamp, stratum!: Int64,
                   rootDelayRaw!: Int64, shiftMs!: Int64): Array<Byte> {
    var out = validResponseBytes()
    out[1] = UInt8(stratum)
    out[4] = UInt8((rootDelayRaw >> 24) & 0xFF)
    out[5] = UInt8((rootDelayRaw >> 16) & 0xFF)
    out[6] = UInt8((rootDelayRaw >> 8) & 0xFF)
    out[7] = UInt8(rootDelayRaw & 0xFF)
    out[24] = UInt8((originate.seconds >> 24) & 0xFF)
    out[25] = UInt8((originate.seconds >> 16) & 0xFF)
    out[26] = UInt8((originate.seconds >> 8) & 0xFF)
    out[27] = UInt8(originate.seconds & 0xFF)
    out[28] = UInt8((originate.fraction >> 24) & 0xFF)
    out[29] = UInt8((originate.fraction >> 16) & 0xFF)
    out[30] = UInt8((originate.fraction >> 8) & 0xFF)
    out[31] = UInt8(originate.fraction & 0xFF)
    let shifted = TimeSync.timestampFromUnixMillis(originate.toNtpEpochMillis() + shiftMs)
    let fields: Array<(Int64, NtpTimestamp)> = [(32, shifted), (40, shifted)]
    for ((off, ts) in fields) {
        out[off] = UInt8((ts.seconds >> 24) & 0xFF)
        out[off + 1] = UInt8((ts.seconds >> 16) & 0xFF)
        out[off + 2] = UInt8((ts.seconds >> 8) & 0xFF)
        out[off + 3] = UInt8(ts.seconds & 0xFF)
        out[off + 4] = UInt8((ts.fraction >> 24) & 0xFF)
        out[off + 5] = UInt8((ts.fraction >> 16) & 0xFF)
        out[off + 6] = UInt8((ts.fraction >> 8) & 0xFF)
        out[off + 7] = UInt8(ts.fraction & 0xFF)
    }
    out
}

/// regression: lower stratum wins even with worse root delay.
func testMultiStratumWins(): Bool {
    let t = MultiEndpointTransport()
    let tsA = TimeSync.timestampFromUnixMillis(0)
    t.reply("a", 123, multiResponse(tsA, stratum: 1, rootDelayRaw: 0x00FFFFFF, shiftMs: 0))
    t.reply("b", 123, multiResponse(tsA, stratum: 2, rootDelayRaw: 0, shiftMs: 0))
    let client = SntpClient(transport: t, clock: FakeClock(readings: [0, 2000, 0, 2000]),
                            timeoutMs: 500)
    client.bind(0)
    let r = client.requestBest(endpoints: [("a", 123), ("b", 123)])
    var ok = r.accepted.size == 2 && r.failed.size == 0
    ok = ok && r.selected.isSome() && r.selected.getOrThrow().endpoint == "a:123"
    client.close()
    ok
}

/// regression: equal stratum -> lower root delay wins.
func testMultiRootDelayTiebreak(): Bool {
    let t = MultiEndpointTransport()
    let tsA = TimeSync.timestampFromUnixMillis(0)
    t.reply("a", 123, multiResponse(tsA, stratum: 2, rootDelayRaw: 0x00010000, shiftMs: 0))
    t.reply("b", 123, multiResponse(tsA, stratum: 2, rootDelayRaw: 0x10, shiftMs: 0))
    let client = SntpClient(transport: t, clock: FakeClock(readings: [0, 2000, 0, 2000]),
                            timeoutMs: 500)
    client.bind(0)
    let r = client.requestBest(endpoints: [("a", 123), ("b", 123)])
    var ok = r.accepted.size == 2
    ok = ok && r.selected.isSome() && r.selected.getOrThrow().endpoint == "b:123"
    // both accepted samples share the stratum/rootDelay; spread computed
    ok = ok && r.spreadMs.isSome()
    client.close()
    ok
}

/// regression: one endpoint timing out never touches the others.
func testMultiFailureIsolation(): Bool {
    let t = MultiEndpointTransport()
    let tsA = TimeSync.timestampFromUnixMillis(0)
    // "dead" endpoint a: no reply registered at all.
    t.reply("b", 123, multiResponse(tsA, stratum: 2, rootDelayRaw: 0, shiftMs: 0))
    let client = SntpClient(transport: t, clock: FakeClock(readings: [0, 0, 0]),
                            timeoutMs: 300)
    client.bind(0)
    let r = client.requestBest(endpoints: [("a", 123), ("b", 123)])
    var ok = r.accepted.size == 1 && r.failed.size == 1
    ok = ok && r.selected.isSome() && r.selected.getOrThrow().endpoint == "b:123"
    ok = ok && r.spreadMs.isNone()
    ok = ok && r.failed[0].endpoint == "a:123"
    client.close()
    ok
}

/// regression: a KoD endpoint is isolated (backoff recorded) and
/// the remaining endpoints still produce a selection.
func testMultiKodIsolation(): Bool {
    let t = MultiEndpointTransport()
    let tsA = TimeSync.timestampFromUnixMillis(0)
    t.reply("kod", 123, kodBytesEchoing(tsA))
    t.reply("good", 123, multiResponse(tsA, stratum: 2, rootDelayRaw: 0, shiftMs: 0))
    let client = SntpClient(transport: t, clock: FakeClock(readings: [0, 0, 0]),
                            timeoutMs: 500)
    client.bind(0)
    let r = client.requestBest(endpoints: [("kod", 123), ("good", 123)])
    var ok = r.accepted.size == 1 && r.failed.size == 1
    ok = ok && r.selected.isSome() && r.selected.getOrThrow().endpoint == "good:123"
    ok = ok && client.kodEndpointCount() >= 1
    client.close()
    ok
}

/// regression: zero accepted endpoints -> selected None, report
/// carries both failures; no exception escapes requestBest.
func testMultiZeroAccepted(): Bool {
    let t = MultiEndpointTransport()
    let client = SntpClient(transport: t, clock: FakeClock(readings: [0, 0]),
                            timeoutMs: 150)
    client.bind(0)
    let r = client.requestBest(endpoints: [("a", 123), ("b", 123)])
    var ok = r.accepted.size == 0 && r.failed.size == 2
    ok = ok && r.selected.isNone() && r.spreadMs.isNone()
    client.close()
    ok
}

/// Low-frequency live pool tier (LIVE_NET=1): exactly one exchange per
/// public endpoint, no retries, no flooding (MA discipline).
func runLiveNetPool(): Int64 {
    println("========================================")
    println("  igNTP LIVE_NET pool conformance (3 exchanges)")
    println("========================================")
    let endpoints: Array<(String, UInt16)> = [
        ("pool.ntp.org", 123), ("time.apple.com", 123), ("time.google.com", 123)
    ]
    let client = SntpClient(transport: UdpNtpTransport(), timeoutMs: 5000)
    client.bind(0)
    let r = client.requestBest(endpoints: endpoints)
    for (entry in r.accepted) {
        println("  ${entry.endpoint}: offset=${entry.sample.offsetMs}ms rtt=${entry.sample.rttMs}ms stratum=${entry.sample.stratum} ref=${entry.sample.referenceIdText()}")
    }
    for (f in r.failed) {
        println("  ${f.endpoint}: FAILED (${f.reason})")
    }
    client.close()
    var ok = true
    if (r.accepted.size < 2) {
        println("  FAIL: fewer than 2 endpoints synchronized (accepted=${r.accepted.size})")
        ok = false
    }
    if (r.selected.isNone()) {
        println("  FAIL: no selection")
        ok = false
    }
    if (let Some(spread) <- r.spreadMs) {
        println("  spread=${spread}ms")
        if (spread >= 1000) {
            println("  FAIL: accepted offset spread ${spread}ms >= 1000ms")
            ok = false
        }
    }
    for (entry in r.accepted) {
        let o = entry.sample.offsetMs
        if (o > 5000 || o < -5000) {
            println("  FAIL: ${entry.endpoint} offset ${o}ms out of sanity window")
            ok = false
        }
    }
    if (ok) {
        println("  LIVE_NET PASS")
        0
    } else {
        println("  LIVE_NET FAIL")
        1
    }
}


// ---- regression pass2 discriminators ----

/// M1: a 48-byte datagram with reserved mode 6 (VN=4, LI=0) currently
/// escapes NtpPacketCodec.decode as a fatal DecodeError and kills the
/// exchange. After the fix it is discarded and a subsequent valid
/// response still wins.
func pass2ReservedModeDiscarded(): Bool {
    let bad = validResponseBytes()
    bad[0] = UInt8(0x26) // LI=0, VN=4, mode=6 (reserved for control)
    let good = validResponseBytes()
    let t = ScriptableNtpTransport()
    t.feed(bad)
    t.feed(good)
    let clock = FakeClock(readings: [0, 1250])
    let client = SntpClient(transport: t, clock: clock, timeoutMs: 500)
    client.bind(0)
    var ok = false
    try {
        let r = client.request(host: "test-host")
        ok = r.stratum == 2
    } catch (e: Exception) {
        println("  [pass2] mode-6 datagram killed the exchange: ${e}")
        ok = false
    }
    ok
}

/// M2: the codec's exactly-48-byte contract must hold in both
/// directions; trailing bytes are currently silently ignored.
func pass2DecodeRejectsOversized(): Bool {
    let base = validResponseBytes()
    let oversized = ArrayList<Byte>()
    for (b in base) {
        oversized.add(b)
    }
    oversized.add(UInt8(0xFF))
    let captured = oversized.toArray()
    throwsNtp({ => NtpPacketCodec.decode(captured) })
}

/// M3: encoding a 32-bit field above 0xFFFFFFFF must throw EncodeError
/// instead of silently truncating to the low 32 bits.
func pass2EncodeRejectsOverflow(): Bool {
    let pkt = NtpPacket(
        leapIndicator: LeapIndicator.NoWarning,
        version: 4,
        mode: NtpMode.Client,
        stratum: 0,
        rootDelay: 0x100000000)
    let threw = try {
        NtpPacketCodec.encode(pkt)
        false
    } catch (e: NtpException) {
        e.code == NtpErrorCode.EncodeError
    } catch (_: Exception) {
        false
    }
    threw
}

main(): Int64 {
    println("========================================")
    println("  igNTP Test Front Door (SNTP v4 / RFC 4330)")
    println("========================================")
    println("")

    // regression stability tier: continuous soak window mode.
    let soakMode = getVariable("NTP_MODE")
    match (soakMode) {
        case Some(m) =>
            if (m == "soak-window") {
                return runSoakWindow()
            }
        case None => ()
    }

    // Low-frequency live pool tier: opt-in via LIVE_NET=1 (public NTP
    // servers, one exchange per endpoint, no retries — MA discipline).
    let isLiveNet = match (getVariable("LIVE_NET")) {
        case Some(_) => true
        case None => false
    }
    if (isLiveNet) {
        return runLiveNetPool()
    }

    check("epoch conversion unix<->ntp + fraction precision", testEpochConversion())
    check("timestampFromUnixMillis whole + fractional", testTimestampFromUnixMillis())
    check("on-wire offset/delay math (+500ms/+1000ms)", testOffsetDelayMath())
    check("request fixture byte-exact (0x23, echo round-trip)", testRequestFixture())
    check("response fixture field parsing (GPS/stratum/poll)", testResponseParse())
    check("client successful exchange (offset 500, rtt 1000)", testClientSuccessfulExchange())
    check("anti-replay: originate mismatch discarded, exchange continues", testAntiReplayRejectsNonEchoedOriginate())
    check("Kiss-o'-Death (RATE) -> KissOfDeathReceived with code", testKissOfDeathSurfacesCode())
    check("unsynchronized (LI=3) -> Unsynchronized", testUnsynchronizedRejected())
    check("version mismatch discarded, exchange continues", testVersionMismatchRejected())
    check("mode mismatch (reflection) discarded, exchange continues", testModeMismatchRejected())
    check("short datagram -> DecodeError", testShortDatagramRejected())
    check("closed transport fails fast (ConnectionClosed)", testClosedTransportFailsFast())

    // regression RED tests (expected FAIL before the fix)
    check("[RED] budget expires despite wall step backward", testBudgetExpiresDespiteWallStepBackward())
    check("[GREEN] KoD backoff is per-endpoint, not global", testKodBackoffIsPerEndpoint())
    check("stratum range rejected (0 and >=16)", testStratumRangeRejected())
    check("wrong-source flood terminates at deadline", testWrongSourceFloodTerminatesAtDeadline())

    // regression RED tests (expected FAIL before the fix)
    check("[regression RED] continuous wrong-source flood terminates at budget", testContinuousWrongSourceFloodTerminates())
    check("[regression RED] KoD from resolved IP blocks hostname retry (zero re-send)", testKodFromResolvedIpBlocksHostnameRetry())
    check("[regression GREEN] KoD backoff isolated across ports and hosts", testKodBackoffIsolatedAcrossPortsAndHosts())
    check("[regression GREEN] KoD backoff map capacity-bounded (64)", testKodBackoffMapBounded())

    // regression regressions
    check("spoofed source dropped (Timeout, not accepted)", testSpoofedSourceDropped())
    check("expected source accepted", testExpectedSourceAccepted())
    check("response from wrong UDP port is dropped", testWrongSourcePortDropped())
    check("KoD backoff blocks immediate retry without wire traffic", testKodBackoffBlocksImmediateRetry())
    check("KoD backoff expires and request returns to wire", testKodBackoffExpires())
    check("zero transmit response discarded, exchange continues", testZeroTransmitResponseRejected())
    check("negative offset floor rounding", testNegativeOffsetFloorRounding())
    check("pre-era timestamp rejected", testPreEraTimestampRejected())

    // ---- regression: deep audit pass2 (failing-first) ----
    check("[P2-RED] pass2: reserved-mode (6) datagram discarded, exchange continues",
        pass2ReservedModeDiscarded())
    check("[P3-RED] pass2: decode rejects datagram larger than 48 bytes",
        pass2DecodeRejectsOversized())
    check("[P3-RED] pass2: encode rejects 32-bit field overflow (no silent truncation)",
        pass2EncodeRejectsOverflow())

    println("")
    println("========================================")
    // ---- regression: deep security audit ----
    check("audit: garbage-then-valid -> the valid response wins",
        deepAuditGarbageThenValidSucceeds())
    check("audit: replayed-originate datagram discarded, exchange continues",
        deepAuditReplayDiscardedThenValidSucceeds())
    check("audit: oversized datagram (>48B) skipped, exchange continues",
        deepAuditOversizedDatagramSkipped())
    check("audit: garbage-only source still ends in Timeout (budget intact)",
        deepAuditGarbageOnlyTimesOut())

    // regression: multi-server convergence
    check("multi: lower stratum wins selection", testMultiStratumWins())
    check("multi: root delay tie-break", testMultiRootDelayTiebreak())
    check("multi: endpoint failure isolated", testMultiFailureIsolation())
    check("multi: KoD endpoint isolated, others selected", testMultiKodIsolation())
    check("multi: zero accepted -> selected None, report only", testMultiZeroAccepted())

    println("  RESULT: ${passCount} passed, ${failCount} failed")
    println("========================================")
    if (failCount > 0) {
        println("FAIL: ${failCount} check(s) failed — exiting non-zero")
        1
    } else {
        0
    }
}


/// MA coverage: stratum out of range (0 without LI=3, or >=16) is a
/// protocol violation.
func testStratumRangeRejected(): Bool {
    // regression: out-of-range stratum is discarded; a good
    // response after it succeeds.
    let bytes0 = validResponseBytes()
    bytes0[1] = 0
    let good0 = validResponseBytes()
    var t = ScriptableNtpTransport()
    t.feed(bytes0)
    t.feed(good0)
    let clock0 = FakeClock(readings: [0, 1250])
    let client = SntpClient(transport: t, clock: clock0, timeoutMs: 500)
    client.bind(0)
    var ok = false
    try {
        let r = client.request(host: "test-host")
        ok = r.stratum == 2
    } catch (_: Exception) {
        ok = false
    }

    let bytes16 = validResponseBytes()
    bytes16[1] = 16
    let good16 = validResponseBytes()
    t = ScriptableNtpTransport()
    t.feed(bytes16)
    t.feed(good16)
    let clock16 = FakeClock(readings: [0, 1250])
    let client16 = SntpClient(transport: t, clock: clock16, timeoutMs: 500)
    client16.bind(0)
    var ok16 = false
    try {
        let r = client16.request(host: "test-host")
        ok16 = r.stratum == 2
    } catch (_: Exception) {
        ok16 = false
    }
    ok && ok16
}

/// MA test model: continuous wrong-source datagrams with an advancing
/// clock — the request must terminate at the deadline (Timeout), not
/// spin forever.
func testWrongSourceFloodTerminatesAtDeadline(): Bool {
    let t = ScriptableNtpTransport()
    t.sourceHost = "evil-host"
    for (_ in 0..10) {
        t.feed(validResponseBytes())
    }
    let clock = FakeClock(readings: [0, 0, 0, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000])
    let client = SntpClient(transport: t, clock: clock)
    client.bind(0)
    var timedOut = false
    try {
        client.request(host: "test-host")
    } catch (e: NtpException) {
        timedOut = e.code == NtpErrorCode.Timeout
    } catch (_: Exception) {
        timedOut = false
    }
    timedOut && t.sent.size == 1
}

// ===== regression deep-audit probes =====

/// N1: one invalid datagram from the queried source (VN=3) must be
/// DISCARDED — the exchange continues and the valid response wins.
/// (Pre-fix the first invalid datagram threw ProtocolViolation,
/// killing the whole exchange: one spoofed packet = one DoS.)
func deepAuditGarbageThenValidSucceeds(): Bool {
    let bad = validResponseBytes()
    bad[0] = UInt8(0x1C) // LI=0 VN=3 Mode=4 — wrong version
    let good = validResponseBytes()
    let t = ScriptableNtpTransport()
    t.feed(bad)
    t.feed(good)
    let clock = FakeClock(readings: [0, 1250])
    let client = SntpClient(transport: t, clock: clock, timeoutMs: 500)
    client.bind(0)
    var ok = false
    try {
        let r = client.request(host: "test-host")
        ok = r.stratum == 2
    } catch (e: Exception) {
        println("  [audit] garbage-then-valid threw: ${e}")
        ok = false
    }
    ok
}

/// N2: a replay (originate not echoing our transmit) is discarded and
/// the exchange continues (pre-fix: ReplayRejected throw).
func deepAuditReplayDiscardedThenValidSucceeds(): Bool {
    let bad = validResponseBytes()
    bad[31] = UInt8(0x01) // corrupt originate fraction LSB
    let good = validResponseBytes()
    let t = ScriptableNtpTransport()
    t.feed(bad)
    t.feed(good)
    let clock = FakeClock(readings: [0, 1250])
    let client = SntpClient(transport: t, clock: clock, timeoutMs: 500)
    client.bind(0)
    var ok = false
    try {
        let r = client.request(host: "test-host")
        ok = r.stratum == 2
    } catch (e: Exception) {
        println("  [audit] replay-then-valid threw: ${e}")
        ok = false
    }
    ok
}

/// N3: an OVERSIZED datagram (script reports count 60 with a corrupted
/// 48-byte prefix + junk tail) must be SKIPPED. Pre-fix the 48-byte
/// receive buffer either silently truncated it into a replay throw or,
/// at the socket layer, hid the excess entirely.
func deepAuditOversizedDatagramSkipped(): Bool {
    var oversized = ArrayList<Byte>()
    let bad = validResponseBytes()
    bad[31] = UInt8(0x01)
    for (b in bad) {
        oversized.add(b)
    }
    for (i in 0..12) {
        oversized.add(UInt8(0xAA))
    }
    let good = validResponseBytes()
    let t = ScriptableNtpTransport()
    t.feed(oversized.toArray())
    t.feed(good)
    let clock = FakeClock(readings: [0, 1250])
    let client = SntpClient(transport: t, clock: clock, timeoutMs: 500)
    client.bind(0)
    var ok = false
    try {
        let r = client.request(host: "test-host")
        ok = r.stratum == 2
    } catch (e: Exception) {
        println("  [audit] oversized-then-valid threw: ${e}")
        ok = false
    }
    ok
}

/// N4: a source that only ever sends invalid datagrams still terminates
/// in TIMEOUT at the budget deadline — never in a classification error.
func deepAuditGarbageOnlyTimesOut(): Bool {
    let bad = validResponseBytes()
    bad[0] = UInt8(0x1C)
    let t = ScriptableNtpTransport()
    t.feed(bad)
    let clock = FakeClock(readings: [0])
    let client = SntpClient(transport: t, clock: clock, timeoutMs: 200)
    client.bind(0)
    var timedOut = false
    try {
        client.request(host: "test-host")
    } catch (e: NtpException) {
        timedOut = e.code == NtpErrorCode.Timeout
    } catch (_: Exception) {
        timedOut = false
    }
    timedOut
}
