#!/usr/bin/env bash
#
# health-check.sh — Aegis WAF Health Check
#
# Usage: health-check.sh [config_dir]
#   config_dir defaults to /etc/aegis-waf
#
# Exit codes:
#   0 - All checks passed (healthy)
#   1 - One or more checks failed
#

set -euo pipefail

CONF_DIR="${1:-/etc/aegis-waf}"
BINARY="/usr/local/bin/aegis-waf"
CERT_DIR="${CONF_DIR}/tls"

FAILURES=0
WARNINGS=0
CHECKS=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass() {
    CHECKS=$((CHECKS + 1))
    echo -e "  ${GREEN}[PASS]${NC} $1"
}

fail() {
    CHECKS=$((CHECKS + 1))
    FAILURES=$((FAILURES + 1))
    echo -e "  ${RED}[FAIL]${NC} $1" >&2
}

warn() {
    CHECKS=$((CHECKS + 1))
    WARNINGS=$((WARNINGS + 1))
    echo -e "  ${YELLOW}[WARN]${NC} $1"
}

info() {
    echo -e "  ${BLUE}[INFO]${NC} $1"
}

# ─── Check 1: Is the aegis-waf process running? ─────────────────────────────

check_process_running() {
    info "Checking if aegis-waf process is running..."

    if pgrep -f "${BINARY}" > /dev/null 2>&1; then
        local pid
        pid=$(pgrep -f "${BINARY}" | head -1)
        local pid_count
        pid_count=$(pgrep -f "${BINARY}" | wc -l)
        pass "Process is running (PID: ${pid}, instances: ${pid_count})"

        # Check CPU / memory usage
        if command -v ps &>/dev/null; then
            local rss cpu
            rss=$(ps -p "${pid}" -o rss= 2>/dev/null | tr -d ' ' || echo "unknown")
            cpu=$(ps -p "${pid}" -o %cpu= 2>/dev/null | tr -d ' ' || echo "unknown")
            info "Memory: ${rss} KB | CPU: ${cpu}%"
        fi
    else
        warn "Process is not running — the service may not be started"
    fi
}

# ─── Check 2: Does the config file exist and is it valid? ───────────────────

check_config() {
    local config_file="${CONF_DIR}/aegis-waf.toml"
    info "Checking configuration file: ${config_file}"

    if [ ! -f "${config_file}" ]; then
        fail "Configuration file not found at ${config_file}"
        return
    fi

    if [ ! -r "${config_file}" ]; then
        fail "Configuration file is not readable"
        return
    fi

    # Check ownership
    local owner
    owner=$(stat -c '%U' "${config_file}" 2>/dev/null || stat -f '%Su' "${config_file}" 2>/dev/null || echo "unknown")
    info "Config owner: ${owner}"

    # Check permissions (should not be world-readable)
    local perms
    perms=$(stat -c '%a' "${config_file}" 2>/dev/null || stat -f '%Lp' "${config_file}" 2>/dev/null || echo "000")
    if [ "${perms}" -gt 640 ] 2>/dev/null; then
        warn "Configuration file permissions are too open: ${perms} (should be <= 640)"
    fi

    # Basic TOML structure validation (check for required sections)
    if grep -q '^\s*\[server\]' "${config_file}" 2>/dev/null; then
        info "[server] section present"
    else
        warn "[server] section not found in config"
    fi

    if grep -q '^\s*\[proxy\]' "${config_file}" 2>/dev/null; then
        info "[proxy] section present"
    else
        info "[proxy] section not found (optional)"
    fi

    pass "Configuration file exists and is readable"
}

# ─── Check 3: Port availability ─────────────────────────────────────────────

check_port() {
    local config_file="${CONF_DIR}/aegis-waf.toml"
    local port=8443

    if [ -f "${config_file}" ]; then
        local cfg_port
        cfg_port=$(grep -E '^\s*listen_port\s*=' "${config_file}" 2>/dev/null | grep -oP '\d+' | head -1 || true)
        if [ -n "${cfg_port}" ]; then
            port="${cfg_port}"
        fi
    fi

    info "Checking port ${port} availability..."

    # Check if the port is being listened on
    local listening
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        local proc_info
        proc_info=$(ss -tlnp 2>/dev/null | grep ":${port} " | head -1)
        pass "Port ${port} is in use (listening): ${proc_info}"
    elif command -v lsof &>/dev/null && lsof -i ":${port}" -sTCP:LISTEN &>/dev/null; then
        pass "Port ${port} is in use (listening via lsof)"
    elif netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
        pass "Port ${port} is in use (listening via netstat)"
    else
        warn "Port ${port} is not listening — service may not be fully started"
    fi

    # Check if port is reachable (only if curl is available)
    if command -v curl &>/dev/null; then
        if curl -sk --connect-timeout 3 "https://127.0.0.1:${port}/" > /dev/null 2>&1; then
            pass "Port ${port} is reachable via HTTPS"
        else
            warn "Port ${port} is not reachable via curl (may not be HTTPS or service not ready)"
        fi
    fi
}

# ─── Check 4: TLS certificate validity ──────────────────────────────────────

check_tls() {
    local cert_file="${CERT_DIR}/server.crt"
    local key_file="${CERT_DIR}/server.key"

    info "Checking TLS certificates..."

    if [ ! -f "${cert_file}" ]; then
        warn "TLS certificate not found at ${cert_file}"
        return
    fi

    if [ ! -f "${key_file}" ]; then
        warn "TLS private key not found at ${key_file}"
    else
        # Check key permissions
        local key_perms
        key_perms=$(stat -c '%a' "${key_file}" 2>/dev/null || stat -f '%Lp' "${key_file}" 2>/dev/null || echo "000")
        if [ "${key_perms}" != "600" ]; then
            warn "Private key permissions are ${key_perms} (should be 600)"
        else
            info "Private key permissions are correct (600)"
        fi
    fi

    # Check if the cert is a valid x509 certificate
    if openssl x509 -in "${cert_file}" -noout 2>/dev/null; then
        info "Certificate is valid X.509"
    else
        fail "Certificate is not a valid X.509 certificate"
        return
    fi

    # Check expiration
    local end_date
    end_date=$(openssl x509 -in "${cert_file}" -noout -enddate 2>/dev/null | cut -d= -f2)
    local remaining_days=0

    if command -v python3 &>/dev/null; then
        remaining_days=$(python3 -c "
import datetime, sys
try:
    end = datetime.datetime.strptime('${end_date}', '%b %d %H:%M:%S %Y %Z')
    remaining = (end - datetime.datetime.utcnow()).days
    print(remaining)
except Exception:
    print(-1)
" 2>/dev/null || echo "-1")
    fi

    if [ "${remaining_days}" -lt 0 ] 2>/dev/null; then
        fail "TLS certificate has EXPIRED (end date: ${end_date})"
    elif [ "${remaining_days}" -lt 30 ] 2>/dev/null; then
        warn "TLS certificate expires in ${remaining_days} days (${end_date})"
    else
        pass "TLS certificate is valid (expires: ${end_date}, ${remaining_days} days remaining)"
    fi

    # Check certificate subject
    local subject
    subject=$(openssl x509 -in "${cert_file}" -noout -subject 2>/dev/null)
    info "Certificate subject: ${subject}"

    # Verify key matches cert
    local cert_md5 key_md5
    cert_md5=$(openssl x509 -noout -modulus -in "${cert_file}" 2>/dev/null | openssl md5 2>/dev/null)
    key_md5=$(openssl rsa -noout -modulus -in "${key_file}" 2>/dev/null | openssl md5 2>/dev/null)
    if [ "${cert_md5}" = "${key_md5}" ] && [ -n "${cert_md5}" ]; then
        info "Certificate and private key match"
    else
        warn "Certificate and private key do NOT match"
    fi
}

# ─── Check 5: Directory permissions ─────────────────────────────────────────

check_directories() {
    info "Checking directory permissions..."

    local dirs=(
        "${CONF_DIR}:750"
        "/var/lib/aegis-waf:700"
        "/var/log/aegis-waf:750"
        "/var/run/aegis-waf:750"
    )

    for entry in "${dirs[@]}"; do
        local dir="${entry%%:*}"
        local expected="${entry##*:}"

        if [ ! -d "${dir}" ]; then
            info "Directory does not exist: ${dir} (may be created on first run)"
            continue
        fi

        local actual
        actual=$(stat -c '%a' "${dir}" 2>/dev/null || stat -f '%Lp' "${dir}" 2>/dev/null || echo "000")
        if [ "${actual}" != "${expected}" ]; then
            warn "Directory ${dir} has permissions ${actual} (expected ${expected})"
        else
            info "Directory ${dir} has correct permissions (${expected})"
        fi
    done
}

# ─── Check 6: Log file health ───────────────────────────────────────────────

check_logs() {
    local log_dir="/var/log/aegis-waf"

    if [ ! -d "${log_dir}" ]; then
        info "Log directory does not exist yet"
        return
    fi

    info "Checking log files..."

    local log_count
    log_count=$(find "${log_dir}" -type f 2>/dev/null | wc -l)

    if [ "${log_count}" -gt 0 ]; then
        info "Found ${log_count} log file(s)"

        # Check for recent errors
        local recent_errors
        recent_errors=$(find "${log_dir}" -type f -name "*.log" -mmin -60 \
            -exec grep -ci "error\|fatal\|panic" {} \; 2>/dev/null | awk '{s+=$1} END {print s}')
        if [ "${recent_errors:-0}" -gt 0 ]; then
            warn "Found ${recent_errors} error/fatal/panic entries in logs from the last hour"
        else
            info "No recent error entries in logs"
        fi
    else
        info "No log files found yet"
    fi
}

# ─── Check 7: System resource availability ──────────────────────────────────

check_resources() {
    info "Checking system resources..."

    # Disk space
    local disk_avail disk_pct
    if command -v df &>/dev/null; then
        disk_avail=$(df -h /var 2>/dev/null | awk 'NR==2 {print $4}' || echo "unknown")
        disk_pct=$(df -h /var 2>/dev/null | awk 'NR==2 {print $5}' || echo "unknown")
        info "Disk available on /var: ${disk_avail} (${disk_pct} used)"
    fi

    # Memory
    if command -v free &>/dev/null; then
        local mem_avail
        mem_avail=$(free -h 2>/dev/null | awk '/^Mem:/ {print $7}' || echo "unknown")
        info "Available memory: ${mem_avail}"
    fi

    # File descriptor limits for the service user
    if command -v su &>/dev/null && id "${CONF_DIR##*/}" &>/dev/null; then
        local fd_limit
        fd_limit=$(su -s /bin/sh aegis-waf -c 'ulimit -n' 2>/dev/null || echo "unknown")
        info "File descriptor limit (aegis-waf): ${fd_limit}"
    fi
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    echo ""
    echo "  Aegis WAF — Health Check"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  ============================================="
    echo ""

    check_process_running
    check_config
    check_port
    check_tls
    check_directories
    check_logs
    check_resources

    echo ""
    echo "  ─────────────────────────────────────────────"
    echo "  Checks:  ${CHECKS} total"
    echo "  Passed:  $((CHECKS - FAILURES - WARNINGS))"
    echo "  Warnings: ${WARNINGS}"
    echo "  Failures: ${FAILURES}"
    echo ""

    if [ "${FAILURES}" -gt 0 ]; then
        echo -e "  ${RED}Health check FAILED — ${FAILURES} failure(s) detected${NC}"
        exit 1
    elif [ "${WARNINGS}" -gt 0 ]; then
        echo -e "  ${YELLOW}Health check passed with ${WARNINGS} warning(s)${NC}"
        exit 0
    else
        echo -e "  ${GREEN}All checks passed — system is healthy${NC}"
        exit 0
    fi
}

main "$@"
