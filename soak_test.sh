#!/usr/bin/env bash
# igNTP soak test — stability tier (regression).
#
# In-process scripted multi-endpoint fleet (no network, no broker): each
# round runs requestBest against 4 endpoints under a rotating fault
# profile (all-healthy / dead / KoD / replay+junk injection / offset
# jitter / all-dead) and asserts requestBest coherence — fleet
# accounting, selection identity, spread presence, zero unclassified
# escapes, KoD backoff recording.
#
# Structure (project-set soak pattern):
# - failure propagation: ANY failed round, zero successful rounds, or
#   missing RSS samples makes the script exit NON-ZERO
# - PID attribution: phase 2 runs ONE binary process for the whole
#   window and samples THAT PID's RSS
# - wall-time floor: the continuous window must span at least the
#   requested seconds (fake-instant runs are rejected)
# - no throughput assertions: SNTP exchanges are latency-bound (budget
#   timeouts drive the pace); the stability signal is zero unclassified
#   escapes + isolation invariants + bounded RSS
# - DYLD self-sufficiency: derived from CANGJIE_HOME (caller envs may
#   strip DYLD_*); the wrapper printf must use the guarded form so a
#   CANGJIE_HOME-less caller degrades instead of aborting under set -u
#   (regression)
# - negative selftest (--negative-selftest, regression): proves a
#   fake exit-23 binary is rejected by phase 1, a fake instant exit-0
#   binary is rejected by the wall-time floor, and — binary built — an
#   honest real-binary control passes
#
# LIVE_NET long-window consistency is intentionally NOT part of this
# script: public-pool traffic stays low-frequency and strictly opt-in
# (LIVE_NET=1 on the test binary; one exchange per endpoint).
#
# Usage (from the igNTP root): bash soak_test.sh [duration_seconds] [--negative-selftest]

DURATION=""
SELFTEST=0
for arg in "$@"; do
    case "$arg" in
        [0-9]*) DURATION="$arg" ;;
        --negative-selftest) SELFTEST=1 ;;
    esac
done
DURATION="${DURATION:-60}"

set -u
if [ -z "${DYLD_LIBRARY_PATH:-}" ] && [ -n "${CANGJIE_HOME:-}" ]; then
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) DYLD_LIBRARY_PATH="${CANGJIE_HOME}/runtime/lib/darwin_aarch64_cjnative" ;;
        Darwin-x86_64) DYLD_LIBRARY_PATH="${CANGJIE_HOME}/runtime/lib/darwin_x86_64_cjnative" ;;
        Linux-x86_64) DYLD_LIBRARY_PATH="${CANGJIE_HOME}/runtime/lib/linux_x86_64_cjnative" ;;
        Linux-aarch64) DYLD_LIBRARY_PATH="${CANGJIE_HOME}/runtime/lib/linux_aarch64_cjnative" ;;
    esac
    export DYLD_LIBRARY_PATH
fi
ROUND_LOG_DIR="/tmp/ignitekit-ntp-soak"
rm -rf "$ROUND_LOG_DIR"
mkdir -p "$ROUND_LOG_DIR"

BIN_WRAP="$ROUND_LOG_DIR/binary-wrapper.sh"
printf '#!/bin/bash\nexport DYLD_LIBRARY_PATH="%s"\nBIN="$1"; shift\nexec "$BIN" "$@"\n' \
    "${DYLD_LIBRARY_PATH:-}" > "$BIN_WRAP"
chmod +x "$BIN_WRAP"

# ---------------------------------------------------------------------------
# run_soak <binary> <duration_seconds> — phase-1 rounds; non-zero on any
# failed round / zero successes.
# ---------------------------------------------------------------------------
run_soak() {
    local BIN="$1" DUR="$2"
    echo "=== igNTP Soak Window (${DUR}s) ==="
    echo "SOAK_START $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "--- Phase 1: repeated soak-window rounds ---"
    local END=$((SECONDS + DUR))
    local ROUNDS=0 PASS_ROUNDS=0 HARD_FAILS=0
    while [ $SECONDS -lt $END ]; do
        ROUNDS=$((ROUNDS + 1))
        local LOG="$ROUND_LOG_DIR/round-$ROUNDS.log"
        if timeout 120 env MULTIPART_MODE= NTP_MODE=soak-window SOAK_ROUNDS=20 \
            "$BIN_WRAP" "$BIN" > "$LOG" 2>&1; then
            PASS_ROUNDS=$((PASS_ROUNDS + 1))
        else
            HARD_FAILS=$((HARD_FAILS + 1))
            echo "ROUND $ROUNDS FAILED (see $LOG)"
            grep 'SOAKWINDOW FAIL' "$LOG" | head -2
        fi
    done
    echo "SOAK_ROUNDS=$ROUNDS PASS_ROUNDS=$PASS_ROUNDS HARD_FAILS=$HARD_FAILS"
    if [ "$PASS_ROUNDS" -lt 1 ]; then
        echo "SOAK_FAIL: zero successful rounds"
        return 1
    fi
    if [ "$HARD_FAILS" -gt 0 ]; then
        echo "SOAK_FAIL: $HARD_FAILS hard-failed rounds"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Phase 2: single-PID continuous window with RSS attribution.
# ---------------------------------------------------------------------------
run_window() {
    local BIN="$1" DUR="$2"
    echo "--- Phase 2: same-PID continuous load window (NTP_MODE=soak-window) ---"
    # Measured round cost ~0.3-0.5s (profiles with dead endpoints burn a
    # real 300ms budget timeout): 4x the requested seconds keeps the
    # window safely past the wall check.
    local WIN_ROUNDS=$((DUR * 4))
    if [ "$WIN_ROUNDS" -gt 7200 ]; then WIN_ROUNDS=7200; fi
    if [ "$WIN_ROUNDS" -lt 90 ]; then WIN_ROUNDS=90; fi
    local BPID SAMPLES SAMPLE_OK=0 RSS_FIRST=0 RSS_LAST=0 RSS
    local W0 W1 SOAK_WALL=0
    W0=$(date +%s)
    env NTP_MODE=soak-window SOAK_ROUNDS="$WIN_ROUNDS" \
        "$BIN_WRAP" "$BIN" > "$ROUND_LOG_DIR/continuous.log" 2>&1 &
    BPID=$!
    echo "BINARY_PID=$BPID ROUNDS=$WIN_ROUNDS"
    SAMPLES=0
    while kill -0 "$BPID" 2>/dev/null; do
        RSS=$(ps -o rss= -p "$BPID" 2>/dev/null | tr -d ' ')
        if [ -n "$RSS" ] && [ "$RSS" -gt 0 ]; then
            SAMPLES=$((SAMPLES + 1))
            if [ "$SAMPLES" -eq 1 ]; then RSS_FIRST=$RSS; fi
            RSS_LAST=$RSS
            SAMPLE_OK=1
        fi
        sleep 0.25
    done
    wait "$BPID" || true
    W1=$(date +%s)
    SOAK_WALL=$((W1 - W0))
    echo "SOAK_WALL=${SOAK_WALL}s (requested ${DUR}s)"
    if [ "$SOAK_WALL" -lt "$DUR" ]; then
        echo "SOAK_FAIL: window undercut (${SOAK_WALL}s < ${DUR}s requested)"
        return 1
    fi
    echo "RSS_SAMPLES=$SAMPLES FIRST=${RSS_FIRST}KB LAST=${RSS_LAST}KB"
    if [ "$SAMPLE_OK" -ne 1 ] || [ "$SAMPLES" -lt 10 ]; then
        echo "SOAK_FAIL: RSS sampling unavailable or too sparse (samples=$SAMPLES)"
        return 1
    fi
    if grep -q 'SOAKWINDOW FAIL' "$ROUND_LOG_DIR/continuous.log" 2>/dev/null; then
        echo "SOAK_FAIL: continuous window reported failed checks"
        grep 'SOAKWINDOW FAIL' "$ROUND_LOG_DIR/continuous.log" | head -3
        return 1
    fi
    if ! grep -q 'SOAKWINDOW PASS' "$ROUND_LOG_DIR/continuous.log" 2>/dev/null; then
        echo "SOAK_FAIL: continuous window did not print SOAKWINDOW PASS (early exit?)"
        return 1
    fi
    grep 'SOAKWINDOW PASS' "$ROUND_LOG_DIR/continuous.log"
    return 0
}

# ---------------------------------------------------------------------------
# Negative selftest (regression): the soak must not accept fake
# success — a failing binary (phase-1 exit codes), an instant exit-0 binary
# (wall-time floor), and — real binary built — the honest short-window
# control (igMQTT regression selftest pattern, adapted to the NTP phase structure).
# ---------------------------------------------------------------------------
negative_selftest() {
    local FAKE_DIR="$ROUND_LOG_DIR/fake"
    rm -rf "$FAKE_DIR"
    mkdir -p "$FAKE_DIR"

    printf '#!/bin/bash\nexit 23\n' > "$FAKE_DIR/fake23"
    chmod +x "$FAKE_DIR/fake23"
    echo ">>> negative control 1: fake binary exits 23 (phase 1 must reject)"
    if run_soak "$FAKE_DIR/fake23" 1 > "$FAKE_DIR/fake23.log" 2>&1; then
        echo "NEGATIVE_CONTROL_1_FAIL: soak accepted exit-23 binary"
        return 1
    fi
    echo "NEGATIVE_CONTROL_1_PASS: exit-23 binary rejected"

    printf '#!/bin/bash\nexit 0\n' > "$FAKE_DIR/fakefast"
    chmod +x "$FAKE_DIR/fakefast"
    echo ">>> negative control 2: fake instant exit-0 (wall floor must reject)"
    if run_soak "$FAKE_DIR/fakefast" 1 > "$FAKE_DIR/fakefast.log" 2>&1 \
        && run_window "$FAKE_DIR/fakefast" 1 >> "$FAKE_DIR/fakefast.log" 2>&1; then
        echo "NEGATIVE_CONTROL_2_FAIL: soak accepted instant exit-0 binary"
        return 1
    fi
    echo "NEGATIVE_CONTROL_2_PASS: instant exit-0 binary rejected"

    if [ ! -f "$BINARY" ]; then
        echo "CONTROL_SKIP: real binary not built — build first for the honest control"
        return 0
    fi
    echo ">>> control: real binary, honest short window (soak must pass)"
    if run_soak "$BINARY" 1 > "$FAKE_DIR/real.log" 2>&1 \
        && run_window "$BINARY" 1 >> "$FAKE_DIR/real.log" 2>&1; then
        echo "CONTROL_PASS: honest real-binary control green"
        return 0
    fi
    echo "CONTROL_FAIL: honest real-binary control failed (see $FAKE_DIR/real.log)"
    return 1
}

# ---------------------------------------------------------------------------
BINARY="$PWD/target/release/bin/igntp_test"
if [ ! -f "$BINARY" ]; then
    echo "SOAK_FAIL: binary not found at $BINARY (cjpm build first)"
    exit 1
fi
echo "Binary: $BINARY"

if [ "$SELFTEST" -eq 1 ]; then
    negative_selftest
    exit $?
fi

if [ "$DURATION" -ge 300 ]; then
    echo ">>> long window requested: proving 30s low-pressure gate first"
    if ! run_soak "$BINARY" 30; then
        echo "GATE_FAIL: 30s low-pressure gate not green — refusing the long window"
        exit 1
    fi
    echo "GATE_PASS: 30s low-pressure gate green — proceeding"
fi

if run_soak "$BINARY" "$DURATION"; then
    if run_window "$BINARY" "$DURATION"; then
        echo "SOAK_END $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "=== Soak Complete: PASS ==="
        exit 0
    else
        echo "SOAK_END $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "=== Soak Complete: FAIL ==="
        exit 1
    fi
else
    echo "SOAK_END $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "=== Soak Complete: FAIL ==="
    exit 1
fi
