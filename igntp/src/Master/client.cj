package igntp.Master

import igntp.Commons.*
import igntp.Features.codec.*
import igntp.Features.timesync.*
import std.collection.*
import std.net.*
import std.sync.*
import std.time.*

/// System clock adapter (production ClockPort).
public class SystemClock <: ClockPort {
    public init() {}
    public func nowUnixMillis(): Int64 {
        DateTime.now().toUnixTimeStamp().toMilliseconds()
    }
}

/// ExchangeBudget bounds one SNTP exchange in time.
/// GREEN (regression D2): monotonic base — expiry depends only
/// on monotonic elapsed vs window; wall steps cannot extend or shorten
/// the budget.
public class ExchangeBudget {
    private let monoStartMs: Int64
    private let windowMs: Int64

    public init(monoStartMs!: Int64, timeoutMs!: Int64) {
        this.monoStartMs = monoStartMs
        this.windowMs = timeoutMs
    }

    public func expired(monoNowMs: Int64): Bool {
        (monoNowMs - monoStartMs) >= windowMs
    }
}

/// KoD backoff record for one endpoint key (regression R4):
/// the deadline lives on the MONOTONIC base — wall steps can neither
/// extend nor shorten a backoff — and the refid travels with it.
public struct KodBackoff {
    public let monoUntilMs: Int64
    public let refId: String

    public init(monoUntilMs: Int64, refId: String) {
        this.monoUntilMs = monoUntilMs
        this.refId = refId
    }
}

/// SNTP v4 unicast client (RFC 4330).
///
/// Response-classification state machine, enumerated before the wait
/// loop (igCoAP F1/F2 knowledge lesson — every message class the peer
/// may send has a defined path). regression HARDENING: packet-
/// level failures are DISCARDED and the exchange continues (RFC 4330
/// §5 — discard and retry); a single spoofed datagram can no longer
/// kill the exchange with a classified throw. Only authoritative server
/// statements and the budget remain terminal:
///   1. datagram < 48 bytes              -> discarded
///   1b. datagram != 48 bytes (oversized) -> discarded (RFC 4330 §4:
///       server messages are exactly 48 bytes; oversized datagrams are
///       not responses to this exchange)
///   2. VN != 4                          -> discarded
///   3. mode not Server/Broadcast        -> discarded
///   4. originate != request transmit    -> discarded (anti-replay:
///       replay/spoof noise never terminates the exchange)
///   5. LI=3 && stratum=0                -> KissOfDeathReceived (code in
///       exception; per-endpoint backoff recorded — authoritative)
///   6. LI=3 otherwise                   -> Unsynchronized (authoritative)
///   7. stratum outside 1..15            -> discarded
///   8. zero transmit timestamp          -> discarded
///   9. valid server/broadcast response  -> SyncResult
///
/// Source validation (RFC 4330 §5, regression F2): responses
/// arriving from an address that does not resolve to the requested host
/// are silently dropped before classification.
///
/// Total budget (regression R1): the exchange budget is checked
/// at the TOP of every wait-loop iteration — i.e. around every receive.
/// A continuous stream of wrong-source datagrams therefore still ends
/// in Timeout at the deadline instead of starving the empty-read-only
/// budget check.
///
/// KoD backoff (§8, F1 + regression R3/R4): after a
/// Kiss-o'-Death the client MUST NOT keep sending to that server. The
/// backoff is stored under a UNIFIED endpoint key set — the literal
/// host plus every address it resolves to — so a KoD from a resolved IP
/// also blocks retries addressed by hostname, while a different host or
/// a different port keeps its own isolated bucket. Entries live on the
/// monotonic base, expired entries are swept on entry, and the map is
/// capacity-bounded (oldest-expiring eviction at 64 endpoints).
/// `request()` entry during the backoff window throws
/// KissOfDeathReceived immediately without touching the wire. Window is
/// injectable (default 15 minutes).
///
/// Threading: single-owner synchronous API; all sends through the
/// sendMutex chokepoint. One-shot exchange — no automatic retransmission
/// (caller retries; recorded boundary). Clock is injectable for
/// deterministic offset tests.
public class SntpClient {
    /// Capacity bound for the KoD backoff map (regression R4): sweep-then-evict
    /// soonest-expiring keeps the map bounded under hostile endpoint
    /// churn without losing the most urgent send-stop state.
    private let maxKodEndpoints: Int64
    private let transport: NtpTransport
    private let clock: ClockPort
    private let monoClock: MonoClockPort
    private let sendMutex: Mutex
    private let timeoutMs: Int64
    private let kodBackoffMs: Int64

    /// GREEN D1 (per-endpoint KoD) + regression R3/R4: backoff keyed by a
    /// unified endpoint key set ("host:port" and "ip:port" for every
    /// resolved address), monotonic deadlines, capacity-bounded.
    private let kodBackoffs: HashMap<String, KodBackoff>

    public init(transport!: NtpTransport, clock!: ClockPort = SystemClock(),
                monoClock!: MonoClockPort = SystemMonoClock(),
                timeoutMs!: Int64 = 5000, kodBackoffMs!: Int64 = 900000) {
        this.transport = transport
        this.clock = clock
        this.monoClock = monoClock
        this.sendMutex = Mutex()
        this.timeoutMs = timeoutMs
        this.kodBackoffMs = kodBackoffMs
        this.maxKodEndpoints = 64
        this.kodBackoffs = HashMap<String, KodBackoff>()
    }

    /// Bind the local endpoint (0 = OS-assigned).
    public func bind(port: UInt16): Unit {
        transport.bind(port)
    }

    public func isBound(): Bool {
        transport.isOpen()
    }

    /// Diagnostics: number of endpoint keys currently carrying KoD
    /// backoff state (bounded by maxKodEndpoints). Verification surface
    /// for the regression capacity contract.
    public func kodEndpointCount(): Int64 {
        kodBackoffs.size
    }

    /// Perform one SNTP unicast exchange against host:port (server port
    /// is 123 by convention). Returns SyncResult or throws per the
    /// classification above.
    public func request(host!: String, port!: UInt16 = NtpConstants.ntpPort): SyncResult {
        // regression R3: resolve BEFORE the backoff gate so the key set covers
        // both the literal host and every address it resolves to.
        let acceptedSources = resolveSources(host)
        let nowMono = monoNowMs()
        sweepExpiredBackoffs(nowMono)
        enforceBackoff(host, port, acceptedSources, nowMono)

        // Build the client request: LI=0, VN=4, Mode=Client; transmit
        // carries our clock reading for the on-wire computation and the
        // server echoes it back in originate (anti-replay check).
        let transmit = TimeSync.timestampFromUnixMillis(clock.nowUnixMillis())
        let request = NtpPacket(
            leapIndicator: LeapIndicator.NoWarning,
            version: NtpConstants.version,
            mode: NtpMode.Client,
            stratum: 0,
            transmitTimestamp: transmit)
        let wire = NtpPacketCodec.encode(request)

        // Audit N1: receive into an oversized buffer so a datagram
        // LONGER than a response is observable (an undersized buffer
        // silently truncates at the socket layer, and a scripted
        // transport escaped a raw RangeException). Per RFC 4330 §4 the
        // server message is exactly 48 bytes — anything else is skipped.
        let buf = Array<Byte>(1024, repeat: 0)
        let budget = ExchangeBudget(monoStartMs: monoNowMs(), timeoutMs: timeoutMs)
        sendDatagram(host, port, wire)

        while (true) {
            if (!transport.isOpen()) {
                throw NtpException(
                    code: NtpErrorCode.ConnectionClosed,
                    message: "transport closed while awaiting response")
            }
            // regression R1: the budget gates EVERY receive. Wrong-source
            // datagrams `continue` back here, so a continuous flood
            // still hits the deadline instead of starving the check
            // (it used to live only on the empty-read path).
            if (budget.expired(monoNowMs())) {
                throw NtpException(
                    code: NtpErrorCode.Timeout,
                    message: "no response within ${timeoutMs}ms (monotonic)")
            }
            let (count, sourceHost, sourcePort) = transport.receiveFrom(buf)
            if (count > 0) {
                // F2: validate the complete UDP endpoint, not just the
                // address. A valid NTP-shaped packet from another port is
                // not a response to this exchange.
                if (sourcePort != port || !acceptedSources.contains(sourceHost)) {
                    continue
                }
                // Audit N1: server messages are exactly 48 bytes — a
                // longer (or, defensively, shorter) datagram is not a
                // response to this exchange. Skipped, not decoded.
                if (count != NtpConstants.packetSize) {
                    continue
                }
                let packet = copyBytes(buf, count)
                // Pass2 M1: decode sits INSIDE the discard-and-continue
                // envelope. A datagram that cannot be decoded (reserved
                // mode, malformed fields) is exactly the RFC 4330 section 5
                // discard case — letting the DecodeError escape here would
                // let one spoofed datagram kill the whole exchange.
                let response = try {
                    NtpPacketCodec.decode(packet)
                } catch (e: NtpException) {
                    continue
                }

                // 2: version — discard and keep waiting (a spoofed or
                // malformed datagram must not terminate the exchange)
                if (response.version != NtpConstants.version) {
                    continue
                }
                // 3: mode
                if (response.mode != NtpMode.Server && response.mode != NtpMode.Broadcast) {
                    continue
                }
                // 4: anti-replay — originate must echo our transmit
                // (checked whenever transmit was provided).
                if (!transmit.isZero() && response.originateTimestamp != transmit) {
                    continue
                }
                // 5: Kiss-o'-Death (LI=3 + stratum 0) — RFC 4330 §8, with
                // the mandatory PER-ENDPOINT send-stop backoff (F1).
                if (response.isKissOfDeath()) {
                    let refId = response.referenceIdText()
                    recordBackoff(host, port, acceptedSources, sourceHost, refId)
                    throw NtpException(
                        code: NtpErrorCode.KissOfDeathReceived,
                        message: "${refId}")
                }
                // 6: unsynchronized.
                if (response.leapIndicator == LeapIndicator.Alarm) {
                    throw NtpException(
                        code: NtpErrorCode.Unsynchronized,
                        message: "server reports unsynchronized (LI=3)")
                }
                // 7: stratum — discard.
                if (response.stratum < NtpConstants.minServerStratum ||
                    response.stratum > NtpConstants.maxServerStratum) {
                    continue
                }
                // 8: zero transmit would poison the offset result — discard.
                if (response.transmitTimestamp.isZero()) {
                    continue
                }
                // 9: valid — compute offset/delay.
                let destination = TimeSync.timestampFromUnixMillis(clock.nowUnixMillis())
                let offsetMs = TimeSync.offsetMillis(
                    request.transmitTimestamp,
                    response.receiveTimestamp,
                    response.transmitTimestamp,
                    destination)
                let rttMs = TimeSync.delayMillis(
                    request.transmitTimestamp,
                    response.receiveTimestamp,
                    response.transmitTimestamp,
                    destination)
                return SyncResult(
                    offsetMs: offsetMs,
                    rttMs: rttMs,
                    serverTimeUnixMs: response.transmitTimestamp.toUnixEpochMillis(),
                    stratum: response.stratum,
                    referenceId: response.referenceId,
                    rootDelayRaw: response.rootDelay)
            }
            sleep(Duration.millisecond * 5)
        }
        throw NtpException(
            code: NtpErrorCode.Timeout,
            message: "request loop ended unexpectedly")
    }

    /// Exchange with every endpoint once, sequentially, and report the
    /// aggregate (regression). Each endpoint runs the exact
    /// single-exchange semantics of `request` — KoD backoff, exchange
    /// budget, and source validation all apply per endpoint — so one
    /// endpoint's failure (Timeout, KoD, refusal) is recorded in
    /// `failed` and never touches the others. Zero accepted endpoints
    /// yields `selected == None`; the result object is the report.
    public func requestBest(endpoints!: Array<(String, UInt16)>): MultiServerResult {
        let report = MultiServerResult()
        for ((host, port) in endpoints) {
            let label = "${host}:${port}"
            try {
                let sample = request(host: host, port: port)
                report.accepted.add(EndpointSample(endpoint: label, sample: sample))
            } catch (e: NtpException) {
                report.failed.add(EndpointFailure(endpoint: label, reason: "${e}"))
            } catch (e: Exception) {
                report.failed.add(EndpointFailure(endpoint: label, reason: "${e}"))
            }
        }
        report.finish()
        report
    }

    public func close(): Unit {
        transport.close()
    }

    // ---- internals ----

    /// Monotonic reading for budgets and backoff deadlines — immune to
    /// wall steps.
    private func monoNowMs(): Int64 {
        monoClock.monoMs()
    }

    /// Unified endpoint key set for a request target (regression R3): the
    /// literal host plus every resolved address, all under the same
    /// port. A KoD recorded under any one of them blocks the whole set;
    /// a different host or port forms a different set.
    private func backoffKeys(host: String, port: UInt16, acceptedSources: HashSet<String>): ArrayList<String> {
        let keys = ArrayList<String>()
        keys.add("${host}:${port}")
        for (addr in acceptedSources) {
            keys.add("${addr}:${port}")
        }
        keys
    }

    /// Drop expired backoff entries so the map cannot grow without
    /// bound across long uptimes (regression R4).
    private func sweepExpiredBackoffs(nowMono: Int64): Unit {
        let expired = ArrayList<String>()
        for ((key, entry) in kodBackoffs) {
            if (nowMono >= entry.monoUntilMs) {
                expired.add(key)
            }
        }
        for (key in expired) {
            kodBackoffs.remove(key)
        }
    }

    /// Refuse the request while any key in the unified set is under an
    /// active KoD backoff (regression R3); entries found expired are cleared
    /// on sight.
    private func enforceBackoff(host: String, port: UInt16, acceptedSources: HashSet<String>, nowMono: Int64): Unit {
        for (key in backoffKeys(host, port, acceptedSources)) {
            match (kodBackoffs.get(key)) {
                case Some(entry) =>
                    if (nowMono < entry.monoUntilMs) {
                        throw NtpException(
                            code: NtpErrorCode.KissOfDeathReceived,
                            message: "endpoint in KoD backoff (${entry.refId})")
                    }
                    kodBackoffs.remove(key)
                case None => ()
            }
        }
    }

    /// Record a KoD under the unified key set (regression R3) with a monotonic
    /// deadline (regression R4). Capacity-bounded: when full, soonest-expiring
    /// entries are evicted first — the least urgent send-stop state is
    /// sacrificed, never the bound.
    private func recordBackoff(host: String, port: UInt16, acceptedSources: HashSet<String>, sourceHost: String, refId: String): Unit {
        let entry = KodBackoff(monoNowMs() + kodBackoffMs, refId)
        let keys = backoffKeys(host, port, acceptedSources)
        if (sourceHost != host) {
            keys.add("${sourceHost}:${port}")
        }
        for (key in keys) {
            if (!kodBackoffs.contains(key)) {
                while (kodBackoffs.size >= maxKodEndpoints) {
                    evictSoonestExpiring()
                }
            }
            kodBackoffs[key] = entry
        }
    }

    private func evictSoonestExpiring(): Unit {
        var found = false
        var victimKey = ""
        var victimUntil: Int64 = 0
        for ((key, entry) in kodBackoffs) {
            if (!found || entry.monoUntilMs < victimUntil) {
                found = true
                victimKey = key
                victimUntil = entry.monoUntilMs
            }
        }
        if (found) {
            kodBackoffs.remove(victimKey)
        }
    }

    /// Resolve a host into the set of source strings a legitimate
    /// response may carry (all A/AAAA records).
    private func resolveSources(host: String): HashSet<String> {
        let set = HashSet<String>()
        set.add(host)
        try {
            let addrs = IPAddress.resolve(host)
            for (addr in addrs) {
                set.add(addr.toString())
            }
        } catch (_: Exception) {
            // Name resolution unavailable: the literal host itself stays
            // in the set, which covers direct-IP usage fully.
        }
        set
    }

    private func sendDatagram(host: String, port: UInt16, wire: Array<Byte>): Unit {
        synchronized(sendMutex) {
            transport.sendTo(host, port, wire)
        }
    }

    /// Copy count bytes out of the receive buffer.
    private func copyBytes(buf: Array<Byte>, count: Int64): Array<Byte> {
        let out = Array<Byte>(count, repeat: 0)
        for (i in 0..count) {
            out[i] = buf[i]
        }
        out
    }
}
