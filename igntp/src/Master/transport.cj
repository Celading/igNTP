package igntp.Master

import igntp.Commons.*
import std.net.*
import std.time.*

/// Datagram transport seam so tests can substitute scripted transports
/// and NTS (authenticated NTP) can slot in later.
public interface NtpTransport {
    /// Bind a local port (0 = OS-assigned).
    func bind(port: UInt16): Unit

    /// Send one datagram.
    func sendTo(host: String, port: UInt16, data: Array<Byte>): Unit

    /// Receive one datagram. count == 0 means read timeout.
    func receiveFrom(buf: Array<Byte>): (Int64, String, UInt16)

    func close(): Unit

    func isOpen(): Bool
}

/// std.net UDP transport (pure Cangjie runtime; stdx not used).
public class UdpNtpTransport <: NtpTransport {
    private var socket: ?UdpSocket
    private let readTimeout: Duration

    public init(readTimeout!: Duration = Duration.second / 10) {
        this.socket = None
        this.readTimeout = readTimeout
    }

    public func bind(port: UInt16): Unit {
        if (socket.isSome()) {
            throw NtpException(
                code: NtpErrorCode.InvalidArgument,
                message: "transport already bound")
        }
        let s = UdpSocket(bindAt: port)
        s.bind()
        s.receiveTimeout = readTimeout
        socket = Some(s)
    }

    public func sendTo(host: String, port: UInt16, data: Array<Byte>): Unit {
        match (socket) {
            case Some(s) =>
                // IPSocketAddress requires an IP literal; hostnames must be
                // resolved first (DNS A/AAAA lookup via std.net).
                let resolved = IPAddress.resolve(host)
                if (resolved.size == 0) {
                    throw NtpException(
                        code: NtpErrorCode.InvalidArgument,
                        message: "cannot resolve host: ${host}")
                }
                let addr = IPSocketAddress(resolved[0], port)
                try {
                    s.sendTo(addr, data)
                } catch (e: Exception) {
                    throw NtpException(
                        code: NtpErrorCode.ConnectionClosed,
                        message: "sendTo failed: ${e}")
                }
            case None =>
                throw NtpException(
                    code: NtpErrorCode.ConnectionClosed,
                    message: "transport not bound")
        }
    }

    public func receiveFrom(buf: Array<Byte>): (Int64, String, UInt16) {
        match (socket) {
            case Some(s) =>
                try {
                    let (addr, count) = s.receiveFrom(buf)
                    match (addr) {
                        case ipAddr: IPSocketAddress =>
                            (count, ipAddr.address.toString(), ipAddr.port)
                        case _ =>
                            throw NtpException(
                                code: NtpErrorCode.ConnectionClosed,
                                message: "receiveFrom returned a non-IP socket address")
                    }
                } catch (_: SocketTimeoutException) {
                    (0, "", 0)
                } catch (e: NtpException) {
                    throw e
                } catch (e: Exception) {
                    throw NtpException(
                        code: NtpErrorCode.ConnectionClosed,
                        message: "receiveFrom failed: ${e}")
                }
            case None =>
                // igCoAP F5 lesson: closed transport fails fast.
                throw NtpException(
                    code: NtpErrorCode.ConnectionClosed,
                    message: "transport closed while receiving")
        }
    }

    public func close(): Unit {
        match (socket) {
            case Some(s) =>
                s.close()
                socket = None
            case None => ()
        }
    }

    public func isOpen(): Bool {
        socket.isSome()
    }
}

/// Monotonic clock port: budgets live in the monotonic domain so wall
/// steps cannot extend or shorten them (regression D2).
public interface MonoClockPort {
    /// Milliseconds on a strictly non-decreasing base.
    func monoMs(): Int64
}

/// System monotonic clock via std.time MonoTime (verified API surface).
public class SystemMonoClock <: MonoClockPort {
    private let start: MonoTime

    public init() {
        this.start = MonoTime.now()
    }

    public func monoMs(): Int64 {
        (MonoTime.now() - this.start).toMilliseconds()
    }
}
