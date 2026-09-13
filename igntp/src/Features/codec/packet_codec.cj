package igntp.Features.codec

import igntp.Commons.*
import std.collection.*

/// 48-byte SNTP packet codec (RFC 4330 §4).
public class NtpPacketCodec {
    public static func encode(packet: NtpPacket): Array<Byte> {
        if (packet.version < 1 || packet.version > 7) {
            throw NtpException(
                code: NtpErrorCode.EncodeError,
                message: "version out of 3-bit range: ${packet.version}")
        }
        // 32-bit wire fields must be in range — silent truncation would
        // put different values on the wire than the caller asked for
        // (pass2 M3).
        for (field in [packet.rootDelay, packet.rootDispersion,
                       packet.referenceTimestamp.seconds,
                       packet.referenceTimestamp.fraction,
                       packet.originateTimestamp.seconds,
                       packet.originateTimestamp.fraction,
                       packet.receiveTimestamp.seconds,
                       packet.receiveTimestamp.fraction,
                       packet.transmitTimestamp.seconds,
                       packet.transmitTimestamp.fraction]) {
            if (field < 0 || field > 0xFFFFFFFF) {
                throw NtpException(
                    code: NtpErrorCode.EncodeError,
                    message: "32-bit field out of range: ${field}")
            }
        }
        let out = ArrayList<Byte>()
        let first: Int64 = (packet.leapIndicator.value() << 6) |
            (packet.version << 3) | packet.mode.value()
        out.add(UInt8(first & 0xFF))
        out.add(UInt8(packet.stratum & 0xFF))
        out.add(UInt8(packet.poll & 0xFF))
        out.add(UInt8(packet.precision & 0xFF))
        appendUInt32(out, packet.rootDelay)
        appendUInt32(out, packet.rootDispersion)
        if (packet.referenceId.size != 4) {
            throw NtpException(
                code: NtpErrorCode.EncodeError,
                message: "reference id must be 4 bytes")
        }
        for (b in packet.referenceId) {
            out.add(b)
        }
        appendTimestamp(out, packet.referenceTimestamp)
        appendTimestamp(out, packet.originateTimestamp)
        appendTimestamp(out, packet.receiveTimestamp)
        appendTimestamp(out, packet.transmitTimestamp)
        if (out.size != NtpConstants.packetSize) {
            throw NtpException(
                code: NtpErrorCode.EncodeError,
                message: "encoded size ${out.size} != ${NtpConstants.packetSize}")
        }
        out.toArray()
    }

    /// Decode a datagram. SNTP server messages are exactly 48 bytes.
    /// Defensive: short datagrams and out-of-range fields throw; KoD
    /// packets parse normally (callers classify via isKissOfDeath()).
    public static func decode(data: Array<Byte>): NtpPacket {
        // Exactly 48 bytes in BOTH directions (RFC 4330 section 4):
        // trailing bytes must not be silently ignored (pass2 M2).
        if (data.size != NtpConstants.packetSize) {
            throw NtpException(
                code: NtpErrorCode.DecodeError,
                message: "datagram must be exactly ${NtpConstants.packetSize} bytes, got ${data.size}")
        }
        let first = Int64(data[0])
        let li = match (LeapIndicator.fromValue((first >> 6) & 0x03)) {
            case Some(v) => v
            case None =>
                throw NtpException(code: NtpErrorCode.DecodeError, message: "bad leap indicator")
        }
        let version = (first >> 3) & 0x07
        let mode = match (NtpMode.fromValue(first & 0x07)) {
            case Some(v) => v
            case None =>
                throw NtpException(code: NtpErrorCode.DecodeError, message: "reserved mode")
        }
        let stratum = Int64(data[1])
        let poll = signByte(Int64(data[2]))
        let precision = signByte(Int64(data[3]))
        let rootDelay = readUInt32(data, 4)
        let rootDispersion = readUInt32(data, 8)
        let refId = slice(data, 12, 4)
        let referenceTs = readTimestamp(data, 16)
        let originateTs = readTimestamp(data, 24)
        let receiveTs = readTimestamp(data, 32)
        let transmitTs = readTimestamp(data, 40)

        NtpPacket(
            leapIndicator: li,
            version: version,
            mode: mode,
            stratum: stratum,
            poll: poll,
            precision: precision,
            rootDelay: rootDelay,
            rootDispersion: rootDispersion,
            referenceId: refId,
            referenceTimestamp: referenceTs,
            originateTimestamp: originateTs,
            receiveTimestamp: receiveTs,
            transmitTimestamp: transmitTs)
    }

    // ---- internals ----

    private static func signByte(v: Int64): Int64 {
        if (v > 127) {
            return v - 256
        }
        v
    }

    private static func readUInt32(data: Array<Byte>, pos: Int64): Int64 {
        (Int64(data[pos]) << 24) | (Int64(data[pos + 1]) << 16) |
            (Int64(data[pos + 2]) << 8) | Int64(data[pos + 3])
    }

    private static func readTimestamp(data: Array<Byte>, pos: Int64): NtpTimestamp {
        NtpTimestamp(
            seconds: readUInt32(data, pos),
            fraction: readUInt32(data, pos + 4))
    }

    private static func appendUInt32(out: ArrayList<Byte>, v: Int64): Unit {
        out.add(UInt8((v >> 24) & 0xFF))
        out.add(UInt8((v >> 16) & 0xFF))
        out.add(UInt8((v >> 8) & 0xFF))
        out.add(UInt8(v & 0xFF))
    }

    private static func appendTimestamp(out: ArrayList<Byte>, ts: NtpTimestamp): Unit {
        appendUInt32(out, ts.seconds)
        appendUInt32(out, ts.fraction)
    }

    private static func slice(data: Array<Byte>, pos: Int64, count: Int64): Array<Byte> {
        let out = Array<Byte>(count, repeat: 0)
        for (i in 0..count) {
            out[i] = data[pos + i]
        }
        out
    }
}
