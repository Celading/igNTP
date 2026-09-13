package igntp.Commons

/// ---- SNTP v4 / NTP wire model (RFC 4330 §4/§5, RFC 1305 layouts) ----

/// Leap Indicator (2 bits).
public enum LeapIndicator {
    | NoWarning       // 0
    | SixtyOneSecond  // 1 (last minute has 61 s)
    | FiftyNineSecond // 2 (last minute has 59 s)
    | Alarm           // 3 (unsynchronized / Kiss-o'-Death marker)

    public func value(): Int64 {
        match (this) {
            case NoWarning => 0
            case SixtyOneSecond => 1
            case FiftyNineSecond => 2
            case Alarm => 3
        }
    }

    public static func fromValue(v: Int64): ?LeapIndicator {
        match (v) {
            case 0 => Some(NoWarning)
            case 1 => Some(SixtyOneSecond)
            case 2 => Some(FiftyNineSecond)
            case 3 => Some(Alarm)
            case _ => None
        }
    }

    public operator func ==(other: LeapIndicator): Bool {
        this.value() == other.value()
    }

    public operator func !=(other: LeapIndicator): Bool {
        !(this == other)
    }
}

/// NTP mode (3 bits).
public enum NtpMode {
    | Reserved         // 0
    | SymmetricActive  // 1
    | SymmetricPassive // 2
    | Client           // 3
    | Server           // 4
    | Broadcast        // 5

    public func value(): Int64 {
        match (this) {
            case Reserved => 0
            case SymmetricActive => 1
            case SymmetricPassive => 2
            case Client => 3
            case Server => 4
            case Broadcast => 5
        }
    }

    public static func fromValue(v: Int64): ?NtpMode {
        match (v) {
            case 0 => Some(Reserved)
            case 1 => Some(SymmetricActive)
            case 2 => Some(SymmetricPassive)
            case 3 => Some(Client)
            case 4 => Some(Server)
            case 5 => Some(Broadcast)
            case _ => None
        }
    }

    public operator func ==(other: NtpMode): Bool {
        this.value() == other.value()
    }

    public operator func !=(other: NtpMode): Bool {
        !(this == other)
    }

    public func label(): String {
        match (this) {
            case Reserved => "reserved"
            case SymmetricActive => "symmetric-active"
            case SymmetricPassive => "symmetric-passive"
            case Client => "client"
            case Server => "server"
            case Broadcast => "broadcast"
        }
    }
}

/// A 64-bit NTP timestamp: 32 bits seconds since 1900-01-01 (era 0),
/// 32 bits fraction. Stored as raw bytes-order integers.
public struct NtpTimestamp {
    public let seconds: Int64     // 0..2^32-1 (era 0)
    public let fraction: Int64    // 0..2^32-1

    public init(seconds!: Int64, fraction!: Int64) {
        this.seconds = seconds
        this.fraction = fraction
    }

    /// Equality used by the anti-replay check (originate == request
    /// transmit) — full 64-bit comparison.
    public operator func ==(other: NtpTimestamp): Bool {
        seconds == other.seconds && fraction == other.fraction
    }

    public operator func !=(other: NtpTimestamp): Bool {
        !(this == other)
    }

    /// Zero timestamp ("not provided").
    public static func zero(): NtpTimestamp {
        NtpTimestamp(seconds: 0, fraction: 0)
    }

    public func isZero(): Bool {
        seconds == 0 && fraction == 0
    }

    /// Convert to milliseconds relative to the NTP epoch (1900-01-01).
    /// Int64-safe: max ≈ 4.29e12 ms, far below Int64 range.
    public func toNtpEpochMillis(): Int64 {
        seconds * 1000 + (fraction * 1000) / 4294967296
    }

    /// Convert to milliseconds relative to the Unix epoch (1970-01-01).
    public func toUnixEpochMillis(): Int64 {
        toNtpEpochMillis() - NtpConstants.unixNtpEpochOffsetMs
    }
}

/// Kiss-o'-Death (RFC 4330 §8): LI=3 + stratum 0, reference id carries
/// a 4-character ASCII code such as "RATE".
public class KissOfDeath {
    public let refIdCode: String

    public init(refIdCode!: String) {
        this.refIdCode = refIdCode
    }

    public func toString(): String {
        "KissOfDeath(${refIdCode})"
    }
}

/// A parsed SNTP/NTP message (fixed 48-byte layout).
public class NtpPacket {
    public let leapIndicator: LeapIndicator
    public let version: Int64
    public let mode: NtpMode
    public let stratum: Int64
    public let poll: Int64          // signed, log2 seconds
    public let precision: Int64     // signed, log2 seconds
    public let rootDelay: Int64     // 16.16 short format, raw
    public let rootDispersion: Int64
    public let referenceId: Array<Byte>  // 4 bytes
    public let referenceTimestamp: NtpTimestamp
    public let originateTimestamp: NtpTimestamp
    public let receiveTimestamp: NtpTimestamp
    public let transmitTimestamp: NtpTimestamp

    public init(
        leapIndicator!: LeapIndicator,
        version!: Int64,
        mode!: NtpMode,
        stratum!: Int64,
        poll!: Int64 = 0,
        precision!: Int64 = 0,
        rootDelay!: Int64 = 0,
        rootDispersion!: Int64 = 0,
        referenceId!: Array<Byte> = [UInt8(0), UInt8(0), UInt8(0), UInt8(0)],
        referenceTimestamp!: NtpTimestamp = NtpTimestamp.zero(),
        originateTimestamp!: NtpTimestamp = NtpTimestamp.zero(),
        receiveTimestamp!: NtpTimestamp = NtpTimestamp.zero(),
        transmitTimestamp!: NtpTimestamp = NtpTimestamp.zero()
    ) {
        this.leapIndicator = leapIndicator
        this.version = version
        this.mode = mode
        this.stratum = stratum
        this.poll = poll
        this.precision = precision
        this.rootDelay = rootDelay
        this.rootDispersion = rootDispersion
        this.referenceId = referenceId
        this.referenceTimestamp = referenceTimestamp
        this.originateTimestamp = originateTimestamp
        this.receiveTimestamp = receiveTimestamp
        this.transmitTimestamp = transmitTimestamp
    }

    /// Whether this packet is a Kiss-o'-Death (LI=3, stratum 0).
    public func isKissOfDeath(): Bool {
        leapIndicator == LeapIndicator.Alarm && stratum == 0
    }

    /// Reference id rendered as ASCII (KoD codes / primary-source ids).
    /// ASCII-safe: printable bytes pass through; others become "\xNN"
    /// (pool.ntp.org stratum-2 refids are raw IPv4 bytes, not UTF-8).
    public func referenceIdText(): String {
        var result = ""
        for (b in referenceId) {
            if (b >= 0x20 && b < 0x7F) {
                result += String.fromUtf8([b])
            } else {
                let digits = "0123456789abcdef"
                let hi = Int64(b) >> 4
                let lo = Int64(b) & 0x0F
                let runes = digits.toRuneArray()
                result += "\\x" + runes[hi].toString() + runes[lo].toString()
            }
        }
        result
    }
}

/// Injectable clock port (igWebAuthn pattern): the client reads
/// destination time through this seam so tests stay deterministic.
public interface ClockPort {
    /// Current wall clock in Unix-epoch milliseconds.
    func nowUnixMillis(): Int64
}

/// Error model.
public class NtpException <: Exception {
    public let code: Int64

    public init(code!: Int64, message!: String) {
        super(message)
        this.code = code
    }

    public override func toString(): String {
        "NtpException(${code}): ${message}"
    }
}

public class NtpErrorCode {
    public static let EncodeError: Int64 = 1
    public static let DecodeError: Int64 = 2
    public static let ProtocolViolation: Int64 = 3
    public static let InvalidArgument: Int64 = 4
    public static let Timeout: Int64 = 5
    public static let ConnectionClosed: Int64 = 6
    public static let ReplayRejected: Int64 = 7
    public static let Unsynchronized: Int64 = 8
    public static let KissOfDeathReceived: Int64 = 9
}
