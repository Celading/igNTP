package igntp.Commons

/// Scope ruling for igNTP (IgniteKit-* extension lane).
public class igNTPScopeRuling {
    public let extensionName: String
    public let extensionLane: String
    public let belongsToIgniteKit: Bool
    public let belongsToCore: Bool
    public let packageVersion: String

    public init() {
        this.extensionName = "igNTP"
        this.extensionLane = "IgniteKit"
        this.belongsToIgniteKit = true
        this.belongsToCore = false
        this.packageVersion = "0.1.0"
    }
}

/// Boundary constants recorded at seed time (owner-ruled runtime policy).
public class igNTPBoundary {
    /// Pure Cangjie std runtime; stdx is forbidden by owner ruling.
    public static let pureCangjieRuntime: Bool = true
    /// Allowed third-party deps: Ignite / JinguiSSL / SeaJson / lisi via
    /// central registry https://cjpi.ystyle.top/opencj
    public static let centralRegistry: String = "https://cjpi.ystyle.top/opencj"
    /// Owner-recorded boundary note.
    public static let boundaryNote: String = "SNTP v4 (RFC 4330) first; NTS via jinguissl_core later; offset reporting only, no clock mutation"
}

/// ---- SNTP protocol constants ----

public class NtpConstants {
    /// SNTP/NTP version implemented.
    public static let version: Int64 = 4
    /// Well-known NTP UDP port.
    public static let ntpPort: UInt16 = 123
    /// Fixed datagram size (RFC 4330 §4: SNTP uses the 48-byte
    /// header-only format).
    public static let packetSize: Int64 = 48
    /// Unix epoch (1970-01-01) offset from NTP epoch (1900-01-01) in
    /// seconds: 70 years incl. 17 leap days.
    public static let unixNtpEpochOffsetSeconds: Int64 = 2208988800
    /// Same offset in milliseconds.
    public static let unixNtpEpochOffsetMs: Int64 = 2208988800000
    /// Legal stratum range for a usable server response.
    public static let minServerStratum: Int64 = 1
    public static let maxServerStratum: Int64 = 15
}
