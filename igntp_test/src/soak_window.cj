package igntp_test

// regression stability tier: NTP_MODE=soak-window entry.
// One process runs SOAK_ROUNDS multi-endpoint rounds against a scripted
// 4-endpoint fleet with a rotating fault profile (all-healthy / dead
// endpoint / KoD / replay+junk injection / offset jitter / all-dead).
// Every round asserts requestBest coherence: accepted+failed covers the
// fleet, selected is from the accepted set with the best stratum,
// spread presence follows the accepted count, and a fully dead fleet
// yields selected=None without throwing. Endpoint isolation and the
// N1/N6 discard contract are exercised every round by construction.

import igntp.Commons.*
import igntp.Features.timesync.*
import igntp.Master.*
import std.collection.*
import std.convert.*
import std.env.*
import std.time.*

// Fleet endpoints (MultiEndpointTransport claims replies per host).
// IP literals with distinct ports: the regression unified KoD key set carries
// one key per resolved address, so hostnames that DNS-resolve would
// yield resolution-dependent backoff key counts. IP literals keep the
// soak invariants deterministic.
let soakEndpoints: Array<(String, UInt16)> = [("127.0.0.1", 11123),
    ("127.0.0.1", 11124), ("127.0.0.1", 11125), ("127.0.0.1", 11126)]

/// Register the scripted replies for one round according to the fault
/// profile. Returns (expectedAccepted, expectedSelectedEndpoint or "").
func soakFleet(profile: Int64, round: Int64, t: MultiEndpointTransport): (Int64, String) {
    let ts0 = TimeSync.timestampFromUnixMillis(0)
    // Replies per profile (a/b/c/d order; a missing reply = dead endpoint).
    match (profile % 6) {
        case 0 => // all healthy, strata 1/2/2/3
            t.reply("127.0.0.1", 11123, multiResponse(ts0, stratum: 1, rootDelayRaw: 0, shiftMs: 0))
            t.reply("127.0.0.1", 11124, multiResponse(ts0, stratum: 2, rootDelayRaw: 0, shiftMs: 0))
            t.reply("127.0.0.1", 11125, multiResponse(ts0, stratum: 2, rootDelayRaw: 0x10, shiftMs: 0))
            t.reply("127.0.0.1", 11126, multiResponse(ts0, stratum: 3, rootDelayRaw: 0, shiftMs: 0))
            (4, "127.0.0.1:11123")
        case 1 => // a dead
            t.reply("127.0.0.1", 11124, multiResponse(ts0, stratum: 2, rootDelayRaw: 0, shiftMs: 0))
            t.reply("127.0.0.1", 11125, multiResponse(ts0, stratum: 2, rootDelayRaw: 0x10, shiftMs: 0))
            t.reply("127.0.0.1", 11126, multiResponse(ts0, stratum: 3, rootDelayRaw: 0, shiftMs: 0))
            (3, "127.0.0.1:11124")
        case 2 => // a Kiss-o'-Death (RATE)
            t.reply("127.0.0.1", 11123, kodBytesEchoing(ts0))
            t.reply("127.0.0.1", 11124, multiResponse(ts0, stratum: 2, rootDelayRaw: 0, shiftMs: 0))
            t.reply("127.0.0.1", 11125, multiResponse(ts0, stratum: 2, rootDelayRaw: 0x10, shiftMs: 0))
            t.reply("127.0.0.1", 11126, multiResponse(ts0, stratum: 3, rootDelayRaw: 0, shiftMs: 0))
            (3, "127.0.0.1:11124")
        case 3 => // a: replayed-originate + oversized junk, then silence
            let replay = multiResponse(TimeSync.timestampFromUnixMillis(999999),
                stratum: 1, rootDelayRaw: 0, shiftMs: 0)
            t.reply("127.0.0.1", 11123, replay)
            let base = validResponseBytes()
            let oversized = ArrayList<Byte>()
            for (b in base) {
                oversized.add(b)
            }
            oversized.add(UInt8(0x00)) // 49 bytes: RFC 4330 says exactly 48
            t.reply("127.0.0.1", 11123, oversized.toArray())
            t.reply("127.0.0.1", 11124, multiResponse(ts0, stratum: 2, rootDelayRaw: 0, shiftMs: 0))
            t.reply("127.0.0.1", 11125, multiResponse(ts0, stratum: 2, rootDelayRaw: 0x10, shiftMs: 0))
            t.reply("127.0.0.1", 11126, multiResponse(ts0, stratum: 3, rootDelayRaw: 0, shiftMs: 0))
            (3, "127.0.0.1:11124")
        case 4 => // offset jitter on d; stratum selection must still win
            t.reply("127.0.0.1", 11123, multiResponse(ts0, stratum: 1, rootDelayRaw: 0, shiftMs: 0))
            t.reply("127.0.0.1", 11124, multiResponse(ts0, stratum: 2, rootDelayRaw: 0, shiftMs: 900))
            t.reply("127.0.0.1", 11125, multiResponse(ts0, stratum: 3, rootDelayRaw: 0, shiftMs: -900))
            t.reply("127.0.0.1", 11126, multiResponse(ts0, stratum: 4, rootDelayRaw: 0, shiftMs: 450))
            (4, "127.0.0.1:11123")
        case _ => // all dead
            (0, "")
    }
}

/// Clock readings per endpoint: a healthy exchange consumes 2 reads
/// (transmit, destination); a dead/KoD/junk endpoint consumes 1.
func soakReadings(expectedAccepted: Int64): Array<Int64> {
    let out = ArrayList<Int64>()
    let dead = 4 - expectedAccepted
    for (i in 0..dead) {
        out.add(0)
    }
    for (i in 0..expectedAccepted) {
        out.add(0)
        out.add(2000)
    }
    // generous tail: the FakeClock holds the last value on exhaustion
    out.add(2000)
    out.add(2000)
    out.toArray()
}

/// One soak round. Returns ok.
func soakRound(round: Int64): Bool {
    let profile = round % 6
    let t = MultiEndpointTransport()
    let (expectedAccepted, expectedSelected) = soakFleet(profile, round, t)
    let client = SntpClient(transport: t,
        clock: FakeClock(readings: soakReadings(expectedAccepted)),
        timeoutMs: 300)
    client.bind(0)
    var ok = true
    try {
        let r = client.requestBest(endpoints: soakEndpoints)
        // invariant: the fleet is fully accounted for
        if (r.accepted.size + r.failed.size != 4) {
            println("SOAKWINDOW FAIL: round ${round} profile ${profile} fleet accounting ${r.accepted.size}+${r.failed.size} != 4")
            ok = false
        }
        if (r.accepted.size != expectedAccepted) {
            println("SOAKWINDOW FAIL: round ${round} profile ${profile} accepted ${r.accepted.size} != ${expectedAccepted}")
            ok = false
        }
        // selected: presence and identity per profile
        if (expectedSelected == "") {
            if (r.selected.isSome()) {
                println("SOAKWINDOW FAIL: round ${round} profile ${profile} selected should be None")
                ok = false
            }
            if (r.spreadMs.isSome()) {
                println("SOAKWINDOW FAIL: round ${round} profile ${profile} spread should be None")
                ok = false
            }
        } else {
            match (r.selected) {
                case Some(sel) =>
                    if (sel.endpoint != expectedSelected) {
                        println("SOAKWINDOW FAIL: round ${round} profile ${profile} selected ${sel.endpoint} != ${expectedSelected}")
                        ok = false
                    }
                case None =>
                    println("SOAKWINDOW FAIL: round ${round} profile ${profile} selected missing")
                    ok = false
            }
        }
        // spread presence: >= 2 accepted samples required
        if (expectedAccepted >= 2 && r.spreadMs.isNone()) {
            println("SOAKWINDOW FAIL: round ${round} profile ${profile} spread missing")
            ok = false
        }
        // KoD profile: the backoff must have recorded exactly the KoD endpoint
        if (profile % 6 == 2 && client.kodEndpointCount() != 1) {
            println("SOAKWINDOW FAIL: round ${round} profile 2 kodEndpointCount ${client.kodEndpointCount()} != 1")
            ok = false
        }
    } catch (e: Exception) {
        println("SOAKWINDOW FAIL: round ${round} profile ${profile} escaped: ${e}")
        ok = false
    }
    client.close()
    ok
}

public func runSoakWindow(): Int64 {
    let roundsEnv = getVariable("SOAK_ROUNDS")
    let rounds: Int64 = match (roundsEnv) {
        case Some(v) =>
            let parsed: Int64 = try {
                Int64.parse(v)
            } catch (_: Exception) {
                1200
            }
            if (parsed > 0) { parsed } else { 1200 }
        case None => 1200
    }
    println("SOAKWINDOW START rounds=${rounds}")
    var passed: Int64 = 0
    var failed: Int64 = 0
    var round: Int64 = 0
    while (round < rounds) {
        if (soakRound(round)) {
            passed += 1
        } else {
            failed += 1
        }
        round += 1
    }
    if (failed > 0) {
        println("SOAKWINDOW FAIL: rounds=${rounds} passed=${passed} failed=${failed}")
        return 1
    }
    println("SOAKWINDOW PASS rounds=${rounds} passed=${passed} failed=${failed}")
    0
}
