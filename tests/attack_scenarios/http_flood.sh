#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="${0##*/}"
TARGET_URL="${AEGIS_TARGET_URL:-https://127.0.0.1:8443}"
CONCURRENCY="${AEGIS_CONCURRENCY:-50}"
DURATION="${AEGIS_DURATION:-30}"
TOOL="${AEGIS_TOOL:-auto}"
REPORT_FILE="http_flood_report_$(date +%Y%m%d_%H%M%S).txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_metric() { echo -e "${BLUE}[METRIC]${NC} $*"; }

cleanup() {
    log_info "Cleaning up background processes..."
    if [[ -n "${WRK_PID:-}" ]]; then kill "$WRK_PID" 2>/dev/null || true; fi
    if [[ -n "${AB_PID:-}" ]]; then kill "$AB_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

select_tool() {
    if [[ "$TOOL" == "auto" ]]; then
        if command -v wrk &>/dev/null; then
            echo "wrk"
        elif command -v ab &>/dev/null; then
            echo "ab"
        elif command -v siege &>/dev/null; then
            echo "siege"
        else
            log_error "No benchmark tool found (wrk, ab, or siege). Please install one."
            exit 1
        fi
    else
        if ! command -v "$TOOL" &>/dev/null; then
            log_error "Specified tool '$TOOL' not found."
            exit 1
        fi
        echo "$TOOL"
    fi
}

run_wrk_stage() {
    local concurrency="$1"
    local duration="$2"
    local label="$3"
    local output_file="/tmp/wrk_output_${label}.txt"

    log_info "Running wrk: ${concurrency} connections, ${duration}s duration [$label]"

    wrk -t"$((concurrency > 4 ? 4 : concurrency))" \
        -c"$concurrency" \
        -d"${duration}s" \
        --latency \
        "$TARGET_URL" \
        > "$output_file" 2>&1 &
    WRK_PID=$!
    wait "$WRK_PID" || true
    WRK_PID=""

    parse_wrk_output "$output_file" "$label"
}

parse_wrk_output() {
    local file="$1"
    local label="$2"

    local requests_total="N/A"
    local requests_sec="N/A"
    local latency_avg="N/A"
    local errors="N/A"

    if grep -q "Requests/sec" "$file"; then
        requests_total=$(grep "requests in" "$file" | awk '{print $1}')
        requests_sec=$(grep "Requests/sec" "$file" | awk '{print $2}')
        latency_avg=$(grep "Latency" -A 1 "$file" | tail -1 | awk '{print $2}' | sed 's/ms//')
        errors=$(grep "Non-2xx" "$file" | awk '{print $NF}' || echo "0")
    fi

    log_metric "[${label}] Total: $requests_total | RPS: $requests_sec | Latency(avg): ${latency_avg}ms | Non-2xx: $errors"
    echo "  Label: $label | Concurrency: $concurrency | Total: $requests_total | RPS: $requests_sec | Latency(avg): ${latency_avg}ms | Non-2xx: $errors"
}

run_ab_stage() {
    local concurrency="$1"
    local total_requests="$2"
    local label="$3"
    local output_file="/tmp/ab_output_${label}.txt"

    log_info "Running ab: ${concurrency} concurrent, ${total_requests} total requests [$label]"

    ab -k -c "$concurrency" -n "$total_requests" \
        "$TARGET_URL" \
        > "$output_file" 2>&1 &
    AB_PID=$!
    wait "$AB_PID" || true
    AB_PID=""

    parse_ab_output "$output_file" "$label"
}

parse_ab_output() {
    local file="$1"
    local label="$2"

    local requests_sec="N/A"
    local time_per_req="N/A"
    local failed="N/A"

    if grep -q "Requests per second" "$file"; then
        requests_sec=$(grep "Requests per second" "$file" | awk '{print $4}')
        time_per_req=$(grep "Time per request.*mean" "$file" | head -1 | awk '{print $4}')
        failed=$(grep "Failed requests" "$file" | awk '{print $3}' || echo "0")
    fi

    log_metric "[${label}] RPS: $requests_sec | Time/req: ${time_per_req}ms | Failed: $failed"
    echo "  Label: $label | Concurrency: $concurrency_ab | RPS: $requests_sec | Time/req: ${time_per_req}ms | Failed: $failed"
}

generate_report() {
    local tool="$1"
    local start_time="$2"
    local end_time="$3"

    {
        echo "=========================================="
        echo " Aegis WAF HTTP Flood Test Report"
        echo "=========================================="
        echo " Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
        echo " Test Configuration"
        echo "-------------------"
        echo " Target URL:      $TARGET_URL"
        echo " Tool:            $tool"
        echo " Base Concurrency: $CONCURRENCY"
        echo " Base Duration:   ${DURATION}s"
        echo ""
        echo " Test Results"
        echo "------------"
        echo " Start Time:      $start_time"
        echo " End Time:        $end_time"
        echo ""
        echo " Stage Metrics"
        echo "--------------"
        cat /tmp/http_flood_metrics.txt 2>/dev/null || echo " No metrics collected"
        echo ""
        echo " Defense Checklist"
        echo "------------------"
        echo " [ ] Rate limiter triggered (check Aegis logs for 'rate_limit_triggered')"
        echo " [ ] 429 responses returned to flood traffic"
        echo " [ ] Legitimate interleaved requests still served (if applicable)"
        echo " [ ] No service crash or unrecoverable state"
        echo " [ ] Connection limit enforcement observed"
        echo ""
        echo " WAF Health Verification"
        echo "------------------------"
        echo " curl -k https://$TARGET_URL/health"
        echo "=========================================="
    } > "$REPORT_FILE"

    log_info "Report saved to $REPORT_FILE"
}

main() {
    log_info "=== Aegis WAF HTTP Flood Attack Simulation ==="

    local tool
    tool=$(select_tool)
    log_info "Using benchmark tool: $tool"

    local target_host_port
    target_host_port=$(echo "$TARGET_URL" | sed -E 's|https?://||')
    log_info "Target: $TARGET_URL ($target_host_port)"

    log_info "Baseline concurrency: $CONCURRENCY"
    log_info "Baseline duration: ${DURATION}s"
    log_info "=============================================="

    > /tmp/http_flood_metrics.txt

    local start_time end_time
    start_time=$(date -u '+%Y-%m-%d %H:%M:%S')

    case "$tool" in
        wrk)
            log_info "--- Stage 1: Low concurrency baseline ---"
            run_wrk_stage "$((CONCURRENCY / 5 > 1 ? CONCURRENCY / 5 : 1))" "$((DURATION > 5 ? 5 : DURATION))" "stage1_low" >> /tmp/http_flood_metrics.txt

            log_info "--- Stage 2: Medium concurrency ---"
            run_wrk_stage "$((CONCURRENCY / 2))" "$((DURATION / 3 > 5 ? DURATION / 3 : 5))" "stage2_med" >> /tmp/http_flood_metrics.txt

            log_info "--- Stage 3: High concurrency flood ---"
            run_wrk_stage "$CONCURRENCY" "$((DURATION / 3 > 5 ? DURATION / 3 : 5))" "stage3_high" >> /tmp/http_flood_metrics.txt

            log_info "--- Stage 4: Maximum concurrency burst ---"
            run_wrk_stage "$((CONCURRENCY * 2))" "$((DURATION / 5 > 5 ? DURATION / 5 : 5))" "stage4_max" >> /tmp/http_flood_metrics.txt
            ;;
        ab)
            local req_per_stage=$((CONCURRENCY * DURATION / 5))

            log_info "--- Stage 1: Low concurrency ---"
            concurrency_ab="$((CONCURRENCY / 5 > 1 ? CONCURRENCY / 5 : 1))"
            run_ab_stage "$concurrency_ab" "$req_per_stage" "stage1_low" >> /tmp/http_flood_metrics.txt

            log_info "--- Stage 2: Medium concurrency ---"
            concurrency_ab="$((CONCURRENCY / 2))"
            run_ab_stage "$concurrency_ab" "$((req_per_stage * 2))" "stage2_med" >> /tmp/http_flood_metrics.txt

            log_info "--- Stage 3: High concurrency ---"
            concurrency_ab="$CONCURRENCY"
            run_ab_stage "$concurrency_ab" "$((req_per_stage * 2))" "stage3_high" >> /tmp/http_flood_metrics.txt

            log_info "--- Stage 4: Burst concurrency ---"
            concurrency_ab="$((CONCURRENCY * 2))"
            run_ab_stage "$concurrency_ab" "$((req_per_stage * 3))" "stage4_max" >> /tmp/http_flood_metrics.txt
            ;;
        *)
            log_error "Unsupported tool: $tool"
            exit 1
            ;;
    esac

    end_time=$(date -u '+%Y-%m-%d %H:%M:%S')

    log_info "=== HTTP Flood Test Complete ==="

    generate_report "$tool" "$start_time" "$end_time"
}

main "$@"
