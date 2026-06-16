#!/usr/bin/env bash
#
# Aegis WAF - Auto-Installer
# https://github.com/aegis-waf/aegis-waf
#
# Detects OS/arch, sets up directories, copies binaries,
# configures systemd, TLS, and performs health checks.
#

set -euo pipefail

# ─── Constants ───────────────────────────────────────────────────────────────

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

readonly BIN_DIR="${BIN_DIR:-/usr/local/bin}"
readonly CONF_DIR="${CONF_DIR:-/etc/aegis-waf}"
readonly DATA_DIR="${DATA_DIR:-/var/lib/aegis-waf}"
readonly LOG_DIR="${LOG_DIR:-/var/log/aegis-waf}"
readonly RUN_DIR="${RUN_DIR:-/var/run/aegis-waf}"
readonly SHARE_DIR="${SHARE_DIR:-/usr/share/aegis-waf}"

readonly SERVICE_NAME="aegis-waf"
readonly SERVICE_USER="aegis-waf"
readonly SERVICE_GROUP="aegis-waf"

# ─── Color helpers ───────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

step_idx=0

msg_info()    { echo -e "  ${BLUE}[INFO]${NC}    $*"; }
msg_ok()      { echo -e "  ${GREEN}[OK]${NC}      $*"; }
msg_warn()    { echo -e "  ${YELLOW}[WARN]${NC}    $*"; }
msg_err()     { echo -e "  ${RED}[ERROR]${NC}   $*" >&2; }
step_header() {
    step_idx=$((step_idx + 1))
    echo ""
    echo -e "${CYAN}${BOLD}── Step ${step_idx}: $* ──────────────────────────────────────────────${NC}"
    echo ""
}

# ─── Platform detection ──────────────────────────────────────────────────────

detect_os() {
    case "$(uname -s)" in
        Linux)
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                echo "${ID}"
            elif [ -f /etc/redhat-release ]; then
                echo "rhel"
            else
                echo "linux-unknown"
            fi
            ;;
        Darwin)  echo "macos" ;;
        *)       echo "unknown" ;;
    esac
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "${arch}" in
        x86_64|amd64)       echo "x86_64" ;;
        aarch64|arm64)      echo "aarch64" ;;
        armv7l|armhf)       echo "armv7" ;;
        *)                  echo "${arch}" ;;
    esac
}

detect_pkg_manager() {
    local os_id
    os_id="$(detect_os)"
    case "${os_id}" in
        ubuntu|debian|linuxmint|pop|raspbian)   echo "apt" ;;
        centos|rhel|rocky|almalinux|fedora|amzn) echo "yum" ;;
        opensuse*|sles)                          echo "zypper" ;;
        arch|manjaro|endeavouros)                echo "pacman" ;;
        alpine)                                  echo "apk" ;;
        macos)                                   echo "brew" ;;
        *)                                       echo "unknown" ;;
    esac
}

# ─── Pre-flight checks ───────────────────────────────────────────────────────

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        msg_err "This installer must be run as root (use sudo)."
        exit 1
    fi
    msg_ok "Running with root privileges"
}

check_deps() {
    local missing=()
    for cmd in id uname mkdir chown chmod cp systemctl openssl; do
        if ! command -v "${cmd}" &>/dev/null; then
            missing+=("${cmd}")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        msg_err "Missing required commands: ${missing[*]}"
        exit 1
    fi
    msg_ok "Required dependencies are available"
}

check_existing() {
    if [ -d "${CONF_DIR}" ] && [ -f "${CONF_DIR}/aegis-waf.toml" ]; then
        msg_warn "Existing installation detected at ${CONF_DIR}"
        read -r -p "  Overwrite and reinstall? [y/N]: " confirm
        if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
            echo "Installation aborted."
            exit 0
        fi
    fi
}

# ─── Rollback support ────────────────────────────────────────────────────────

BACKUP_DIR=""

setup_rollback() {
    BACKUP_DIR="$(mktemp -d "/tmp/aegis-waf-backup.XXXXXX")"
    msg_info "Backup directory: ${BACKUP_DIR}"

    # Backup existing configs
    if [ -d "${CONF_DIR}" ]; then
        cp -a "${CONF_DIR}" "${BACKUP_DIR}/aegis-waf.conf.bak" 2>/dev/null || true
    fi
    if [ -d "${DATA_DIR}" ]; then
        cp -a "${DATA_DIR}" "${BACKUP_DIR}/aegis-waf.data.bak" 2>/dev/null || true
    fi
    msg_ok "Backup created"
}

perform_rollback() {
    echo ""
    msg_warn "Installation failed. Rolling back changes..."

    if [ -n "${BACKUP_DIR}" ] && [ -d "${BACKUP_DIR}" ]; then
        if [ -d "${BACKUP_DIR}/aegis-waf.conf.bak" ]; then
            rm -rf "${CONF_DIR}" 2>/dev/null || true
            cp -a "${BACKUP_DIR}/aegis-waf.conf.bak" "${CONF_DIR}" 2>/dev/null || true
        fi
        if [ -d "${BACKUP_DIR}/aegis-waf.data.bak" ]; then
            rm -rf "${DATA_DIR}" 2>/dev/null || true
            cp -a "${BACKUP_DIR}/aegis-waf.data.bak" "${DATA_DIR}" 2>/dev/null || true
        fi
        rm -rf "${BACKUP_DIR}" 2>/dev/null || true
    fi

    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || true
    rm -f "${BIN_DIR}/aegis-waf" 2>/dev/null || true

    systemctl daemon-reload 2>/dev/null || true
    msg_err "Rollback complete."
    exit 1
}

trap perform_rollback ERR

# ─── System user / group ─────────────────────────────────────────────────────

create_user() {
    step_header "Creating system user and group"

    if id "${SERVICE_USER}" &>/dev/null; then
        msg_info "User '${SERVICE_USER}' already exists"
    else
        if [ "$(detect_os)" = "macos" ]; then
            dscl . -create "/Users/${SERVICE_USER}" 2>/dev/null || true
            dscl . -create "/Users/${SERVICE_USER}" UserShell /usr/bin/false 2>/dev/null || true
            dscl . -create "/Users/${SERVICE_USER}" UniqueID 550 2>/dev/null || true
            dscl . -create "/Users/${SERVICE_USER}" PrimaryGroupID 550 2>/dev/null || true
            dscl . -create "/Users/${SERVICE_USER}" NFSHomeDirectory /var/empty 2>/dev/null || true
        else
            useradd --system --no-create-home --shell /usr/sbin/nologin \
                --home-dir /var/empty "${SERVICE_USER}" 2>/dev/null || \
            useradd --system --no-create-home --shell /sbin/nologin \
                --home-dir /var/empty "${SERVICE_USER}"
        fi
        msg_ok "Created system user '${SERVICE_USER}'"
    fi

    if ! getent group "${SERVICE_GROUP}" &>/dev/null; then
        if [ "$(detect_os)" = "macos" ]; then
            dscl . -create "/Groups/${SERVICE_GROUP}" 2>/dev/null || true
            dscl . -create "/Groups/${SERVICE_GROUP}" PrimaryGroupID 550 2>/dev/null || true
        else
            groupadd --system "${SERVICE_GROUP}" 2>/dev/null || true
        fi
        msg_ok "Created system group '${SERVICE_GROUP}'"
    fi
}

# ─── Directory setup ─────────────────────────────────────────────────────────

setup_directories() {
    step_header "Creating directory structure"

    for dir in "${CONF_DIR}" "${DATA_DIR}" "${LOG_DIR}" "${RUN_DIR}" "${SHARE_DIR}"; do
        if [ ! -d "${dir}" ]; then
            mkdir -p "${dir}"
            msg_info "Created ${dir}"
        else
            msg_info "Directory exists: ${dir}"
        fi
        chown "${SERVICE_USER}:${SERVICE_GROUP}" "${dir}"
        chmod 750 "${dir}"
    done

    # Data directory needs stricter permissions
    chmod 700 "${DATA_DIR}"

    msg_ok "Directory structure ready"
}

# ─── Copy files ──────────────────────────────────────────────────────────────

copy_binaries() {
    step_header "Installing binaries"

    local src_binary="${PROJECT_ROOT}/bin/aegis-waf"
    local arch
    arch="$(detect_arch)"

    if [ ! -f "${src_binary}" ]; then
        # Check for arch-specific binary
        local arch_binary="${PROJECT_ROOT}/bin/aegis-waf-${arch}"
        if [ -f "${arch_binary}" ]; then
            src_binary="${arch_binary}"
        else
            msg_err "Binary not found: ${src_binary} or ${arch_binary}"
            return 1
        fi
    fi

    cp "${src_binary}" "${BIN_DIR}/aegis-waf"
    chown root:root "${BIN_DIR}/aegis-waf"
    chmod 755 "${BIN_DIR}/aegis-waf"

    msg_ok "Binary installed to ${BIN_DIR}/aegis-waf"
}

copy_configs() {
    step_header "Installing configuration files"

    local src_config="${PROJECT_ROOT}/install/config/default.toml"
    local dest_config="${CONF_DIR}/aegis-waf.toml"

    if [ -f "${src_config}" ]; then
        if [ -f "${dest_config}" ]; then
            cp "${dest_config}" "${dest_config}.bak.$(date +%Y%m%d%H%M%S)"
            msg_info "Backed up existing config"
        fi
        cp "${src_config}" "${dest_config}"
        msg_ok "Configuration installed to ${dest_config}"
    else
        msg_warn "Default config not found at ${src_config}, creating minimal config..."
        cat > "${dest_config}" << 'TOML'
# Aegis WAF - Default Configuration (auto-generated)
[server]
listen_address = "0.0.0.0"
listen_port = 8443

[proxy]
backend = "http://127.0.0.1:8080"

[rate_limit]
enabled = true
requests_per_second = 100
burst = 200
TOML
    fi

    chown "${SERVICE_USER}:${SERVICE_GROUP}" "${dest_config}"
    chmod 640 "${dest_config}"
}

# ─── Systemd service ─────────────────────────────────────────────────────────

setup_systemd() {
    step_header "Setting up systemd service"

    if [ "$(detect_os)" = "macos" ]; then
        msg_warn "systemd not available on macOS — skipping"
        return 0
    fi

    if ! command -v systemctl &>/dev/null; then
        msg_warn "systemctl not found — skipping systemd setup"
        return 0
    fi

    local src_service="${PROJECT_ROOT}/install/systemd/aegis-waf.service"
    local dest_service="/etc/systemd/system/${SERVICE_NAME}.service"

    if [ -f "${src_service}" ]; then
        cp "${src_service}" "${dest_service}"
        chmod 644 "${dest_service}"
    else
        msg_warn "Service file not found, creating default..."
        cat > "${dest_service}" << EOF
[Unit]
Description=Aegis WAF DDoS Protection
Documentation=https://github.com/aegis-waf/aegis-waf
After=network.target redis.service
Wants=network.target

[Service]
Type=notify
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
ExecStart=${BIN_DIR}/aegis-waf service start
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aegis-waf
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths=${DATA_DIR} ${LOG_DIR} ${RUN_DIR}
RuntimeDirectory=aegis-waf
RuntimeDirectoryMode=0750
LimitNOFILE=65536
LimitNPROC=4096
MemoryHigh=2G
MemoryMax=4G

[Install]
WantedBy=multi-user.target
EOF
        chmod 644 "${dest_service}"
    fi

    systemctl daemon-reload
    msg_ok "Systemd service installed"

    read -r -p "  Enable and start aegis-waf service now? [Y/n]: " enable_confirm
    if [[ ! "${enable_confirm}" =~ ^[Nn]$ ]]; then
        systemctl enable "${SERVICE_NAME}" 2>/dev/null || true
        systemctl start "${SERVICE_NAME}" 2>/dev/null || msg_warn "Service start failed — check journalctl -u ${SERVICE_NAME}"
        msg_ok "Service enabled and started"
    else
        msg_info "Service installed but not enabled. Run: systemctl enable --now ${SERVICE_NAME}"
    fi
}

# ─── TLS certificates ────────────────────────────────────────────────────────

setup_tls() {
    step_header "TLS certificate setup"

    local tls_script="${PROJECT_ROOT}/install/scripts/setup-tls.sh"

    if [ -f "${tls_script}" ]; then
        read -r -p "  Set up TLS certificates? [y/N]: " tls_confirm
        if [[ "${tls_confirm}" =~ ^[Yy]$ ]]; then
            bash "${tls_script}" "${CONF_DIR}"
            msg_ok "TLS certificates configured"
        else
            msg_info "Skipping TLS setup"
        fi
    else
        msg_info "TLS setup script not found — generating self-signed cert"
        local cert_dir="${CONF_DIR}/tls"
        mkdir -p "${cert_dir}"
        openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
            -keyout "${cert_dir}/server.key" \
            -out "${cert_dir}/server.crt" \
            -subj "/CN=AegisWAF-SelfSigned" 2>/dev/null
        chmod 600 "${cert_dir}/server.key"
        chmod 644 "${cert_dir}/server.crt"
        chown "${SERVICE_USER}:${SERVICE_GROUP}" "${cert_dir}/server.key" "${cert_dir}/server.crt"
        msg_ok "Self-signed certificate generated"
    fi
}

# ─── Health check ────────────────────────────────────────────────────────────

run_health_check() {
    step_header "Running health check"

    local health_script="${PROJECT_ROOT}/install/scripts/health-check.sh"

    sleep 2  # Give service a moment to start

    if [ -f "${health_script}" ]; then
        if bash "${health_script}" "${CONF_DIR}" 2>/dev/null; then
            msg_ok "Health check PASSED"
        else
            msg_warn "Health check returned warnings — review logs"
        fi
    else
        # Minimal inline health check
        local all_ok=true

        if pgrep -f "${BIN_DIR}/aegis-waf" &>/dev/null; then
            msg_ok "Process is running"
        else
            msg_warn "Process not detected (may not be started yet)"
            all_ok=false
        fi

        if [ -f "${CONF_DIR}/aegis-waf.toml" ]; then
            msg_ok "Configuration file exists"
        else
            msg_err "Configuration file missing"
            all_ok=false
        fi

        if [ -f "${CONF_DIR}/tls/server.crt" ]; then
            if openssl x509 -in "${CONF_DIR}/tls/server.crt" -noout -checkend 0 2>/dev/null; then
                msg_ok "TLS certificate is valid"
            else
                msg_warn "TLS certificate expired or invalid"
            fi
        fi

        if ! ${all_ok}; then
            msg_warn "Some checks failed — review above warnings"
        fi
    fi
}

# ─── Final summary ───────────────────────────────────────────────────────────

print_summary() {
    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║           Aegis WAF Installation Complete!                  ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Binary:${NC}     ${BIN_DIR}/aegis-waf"
    echo -e "  ${BOLD}Config:${NC}     ${CONF_DIR}/aegis-waf.toml"
    echo -e "  ${BOLD}Data:${NC}       ${DATA_DIR}"
    echo -e "  ${BOLD}Logs:${NC}       ${LOG_DIR}"
    echo -e "  ${BOLD}User:${NC}       ${SERVICE_USER}"
    echo ""
    echo -e "  ${BOLD}Quick start:${NC}"
    echo "    sudo systemctl start ${SERVICE_NAME}"
    echo "    sudo journalctl -u ${SERVICE_NAME} -f"
    echo "    curl -k https://localhost:8443"
    echo ""
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    echo ""
    echo -e "${CYAN}${BOLD} ═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}   Aegis WAF Installer v1.0.0${NC}"
    echo -e "${CYAN}${BOLD}   OS: $(detect_os) | Arch: $(detect_arch)${NC}"
    echo -e "${CYAN}${BOLD} ═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    check_root
    check_deps
    check_existing
    setup_rollback

    create_user
    setup_directories
    copy_binaries
    copy_configs
    setup_tls
    setup_systemd
    run_health_check
    print_summary

    rm -rf "${BACKUP_DIR}" 2>/dev/null || true
    trap - ERR
}

main "$@"
