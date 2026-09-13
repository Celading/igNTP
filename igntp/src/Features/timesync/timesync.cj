package igntp.Features.timesync

import igntp.Commons.*
import std.collection.*

/// Epoch conversion and the SNTP on-wire offset/delay computation
/// (RFC 4330 §5: offset = ((t2-t1)+(t3-t4))/2, delay = (t4-t1)-(t3-t2),
/// where t1 = originate (request transmit), t2 = server receive,
/// t3 = server transmit, t4 = destination (client receive)).
public class TimeSync {
    /// Unix-epoch milliseconds → NTP-epoch milliseconds.
    public static func unixToNtpMs(unixMillis: Int64): Int64 {
        unixMillis + NtpConstants.unixNtpEpochOffsetMs
    }

    /// NTP-epoch milliseconds → Unix-epoch milliseconds.
    public static func ntpToUnixMs(ntpMillis: Int64): Int64 {
        ntpMillis - NtpConstants.unixNtpEpochOffsetMs
    }

    /// Build a transmit timestamp from a Unix-epoch millisecond clock
    /// reading (whole seconds + scaled fraction; sub-millisecond residue
    /// is truncated — recorded precision boundary).
    public static func timestampFromUnixMillis(unixMillis: Int64): NtpTimestamp {
        let ntpMillis = unixToNtpMs(unixMillis)
        // F5: times before the NTP era 0 (year 1900) cannot be
        // represented in the unsigned 32-bit seconds field.
        if (ntpMillis < 0) {
            throw NtpException(
                code: NtpErrorCode.InvalidArgument,
                message: "time predates the NTP era (unix < 1900): ${unixMillis}")
        }
        let seconds = floorDiv(ntpMillis, 1000)
        let remainderMs = ntpMillis - seconds * 1000
        // fraction = remainderMs * 2^32 / 1000 (Int64-safe).
        let fraction = (remainderMs * 4294967296) / 1000
        NtpTimestamp(seconds: seconds, fraction: fraction)
    }

    /// On-wire offset in milliseconds: the client clock's estimate of how
    /// far AHEAD the server clock is (add offsetMs to client time to
    /// approximate server time).
    public static func offsetMillis(t1: NtpTimestamp, t2: NtpTimestamp,
                                    t3: NtpTimestamp, t4: NtpTimestamp): Int64 {
        let a = t2.toNtpEpochMillis() - t1.toNtpEpochMillis()
        let b = t3.toNtpEpochMillis() - t4.toNtpEpochMillis()
        // Arithmetic right shift = floor division; Cangjie `/` truncates
        // toward zero, which biases negative offsets by ±1 ms (F4).
        (a + b) >> 1
    }

    /// On-wire round-trip delay in milliseconds.
    public static func delayMillis(t1: NtpTimestamp, t2: NtpTimestamp,
                                   t3: NtpTimestamp, t4: NtpTimestamp): Int64 {
        let a = t4.toNtpEpochMillis() - t1.toNtpEpochMillis()
        let b = t3.toNtpEpochMillis() - t2.toNtpEpochMillis()
        a - b
    }

    private static func floorDiv(a: Int64, b: Int64): Int64 {
        var q = a / b
        if ((a % b != 0) && ((a < 0) != (b < 0))) {
            q -= 1
        }
        q
    }
}

/// The successful outcome of a single SNTP exchange.
public class SyncResult {
    /// Client-clock estimate of (server - client), milliseconds.
    public let offsetMs: Int64
    /// Round-trip delay, milliseconds.
    public let rttMs: Int64
    /// Server transmit timestamp as Unix-epoch milliseconds.
    public let serverTimeUnixMs: Int64
    /// Server stratum (1 = primary reference).
    public let stratum: Int64
    /// Server reference id (ASCII for primary sources, e.g. "GPS").
    public let referenceId: Array<Byte>
    /// Server root delay, raw 16.16 short format (regression:
    /// selection tie-break input). 0 when unknown.
    public let rootDelayRaw: Int64

    public init(offsetMs!: Int64, rttMs!: Int64, serverTimeUnixMs!: Int64,
                stratum!: Int64, referenceId!: Array<Byte>,
                rootDelayRaw!: Int64 = 0) {
        this.offsetMs = offsetMs
        this.rttMs = rttMs
        this.serverTimeUnixMs = serverTimeUnixMs
        this.stratum = stratum
        this.referenceId = referenceId
        this.rootDelayRaw = rootDelayRaw
    }

    /// Reference id rendered as ASCII for stratum 1 (primary sources,
    /// e.g. "GPS"), or as dotted-quad IPv4 for stratum 2+ (upstream sync
    /// address). Non-UTF8-safe bytes never reach String.fromUtf8.
    public func referenceIdText(): String {
        if (stratum == 1) {
            return asciiSafe(referenceId)
        }
        if (referenceId.size == 4) {
            return "${Int64(referenceId[0])}.${Int64(referenceId[1])}.${Int64(referenceId[2])}.${Int64(referenceId[3])}"
        }
        return asciiSafe(referenceId)
    }

    /// ASCII-safe rendering: printable bytes pass through, others become
    /// "\xNN" escapes (no exceptions, no invalid UTF-8).
    func asciiSafe(bytes: Array<Byte>): String {
        var result = ""
        for (b in bytes) {
            if (b >= 0x20 && b < 0x7F) {
                result += String.fromUtf8([b])
            } else {
                result += "\\x" + hexByte(b)
            }
        }
        result
    }

    func hexByte(b: Byte): String {
        let digits = "0123456789abcdef"
        let hi = Int64(b) >> 4
        let lo = Int64(b) & 0x0F
        let runes = digits.toRuneArray()
        runes[hi].toString() + runes[lo].toString()
    }

    public func toString(): String {
        "SyncResult(offsetMs=${offsetMs}, rttMs=${rttMs}, stratum=${stratum}, ref=${referenceIdText()})"
    }
}
/// One accepted per-endpoint sample of a multi-server run
/// (regression).
public class EndpointSample {
    public let endpoint: String
    public let sample: SyncResult

    public init(endpoint!: String, sample!: SyncResult) {
        this.endpoint = endpoint
        this.sample = sample
    }
}

/// One failed per-endpoint outcome of a multi-server run.
public class EndpointFailure {
    public let endpoint: String
    public let reason: String

    public init(endpoint!: String, reason!: String) {
        this.endpoint = endpoint
        this.reason = reason
    }
}

/// Aggregate outcome of `SntpClient.requestBest`: every endpoint's
/// outcome is reported (accepted sample or failure reason), the best
/// sample is selected by (stratum asc, rootDelay asc, rtt asc), and the
/// offset spread across accepted samples is reported when two or more
/// were accepted. `selected == None` means no endpoint produced a valid
/// exchange — the object is the report; callers decide policy.
public class MultiServerResult {
    public let accepted: ArrayList<EndpointSample>
    public let failed: ArrayList<EndpointFailure>
    public var selected: ?EndpointSample
    public var spreadMs: ?Int64

    public init() {
        this.accepted = ArrayList<EndpointSample>()
        this.failed = ArrayList<EndpointFailure>()
        this.selected = None
        this.spreadMs = None
    }

    /// Select best by (stratum, rootDelay, rtt), all ascending, and
    /// compute the offset spread across accepted samples.
    public func finish(): Unit {
        if (accepted.size == 0) {
            selected = None
            spreadMs = None
            return
        }
        var best = accepted[0]
        for (entry in accepted) {
            let s = entry.sample
            let b = best.sample
            if (s.stratum < b.stratum) {
                best = entry
            } else if (s.stratum == b.stratum) {
                if (s.rootDelayRaw < b.rootDelayRaw) {
                    best = entry
                } else if (s.rootDelayRaw == b.rootDelayRaw && s.rttMs < b.rttMs) {
                    best = entry
                }
            }
        }
        selected = Some(best)
        if (accepted.size >= 2) {
            var minOff = accepted[0].sample.offsetMs
            var maxOff = minOff
            for (entry in accepted) {
                if (entry.sample.offsetMs < minOff) {
                    minOff = entry.sample.offsetMs
                }
                if (entry.sample.offsetMs > maxOff) {
                    maxOff = entry.sample.offsetMs
                }
            }
            spreadMs = Some(maxOff - minOff)
        } else {
            spreadMs = None
        }
    }
}
