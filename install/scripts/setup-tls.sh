#!/usr/bin/env bash
#
# setup-tls.sh — Aegis WAF TLS Certificate Setup
#
# Usage: setup-tls.sh [config_dir]
#   config_dir defaults to /etc/aegis-waf
#

set -euo pipefail

CONF_DIR="${1:-/etc/aegis-waf}"
CERT_DIR="${CONF_DIR}/tls"
SERVICE_USER="aegis-waf"
SERVICE_GROUP="aegis-waf"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

msg_info()  { echo -e "  ${BLUE}[INFO]${NC}    $*"; }
msg_ok()    { echo -e "  ${GREEN}[OK]${NC}      $*"; }
msg_warn()  { echo -e "  ${YELLOW}[WARN]${NC}    $*"; }
msg_err()   { echo -e "  ${RED}[ERROR]${NC}   $*" >&2; }

# ─── Prerequisites ──────────────────────────────────────────────────────────

check_prereqs() {
    if ! command -v openssl &>/dev/null; then
        msg_err "openssl is required but not installed."
        exit 1
    fi
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        msg_err "This script must be run as root (use sudo)."
        exit 1
    fi
}

# ─── Self-signed certificate ────────────────────────────────────────────────

generate_self_signed() {
    local domain="${1:-localhost}"
    local key_file="${CERT_DIR}/server.key"
    local crt_file="${CERT_DIR}/server.crt"

    msg_info "Generating self-signed certificate for ${domain}"

    mkdir -p "${CERT_DIR}"

    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout "${key_file}" \
        -out "${crt_file}" \
        -subj "/CN=${domain}" \
        -addext "subjectAltName=DNS:${domain},DNS:*.${domain},IP:127.0.0.1" \
        2>/dev/null

    chmod 600 "${key_file}"
    chmod 644 "${crt_file}"

    if id "${SERVICE_USER}" &>/dev/null; then
        chown "${SERVICE_USER}:${SERVICE_GROUP}" "${key_file}" "${crt_file}"
    fi

    msg_ok "Self-signed certificate created"
    msg_info "Key:  ${key_file}"
    msg_info "Cert: ${crt_file}"
    msg_warn "Self-signed certs are NOT trusted by browsers. Use Let's Encrypt for production."

    # Verify the certificate
    if openssl x509 -in "${crt_file}" -noout -subject -dates 2>/dev/null; then
        msg_ok "Certificate verification passed"
    else
        msg_err "Certificate verification failed"
        return 1
    fi
}

# ─── Let's Encrypt via certbot ───────────────────────────────────────────────

setup_letsencrypt() {
    local domain="$1"

    if ! command -v certbot &>/dev/null; then
        msg_err "certbot is not installed. Install it first or use self-signed mode."
        return 1
    fi

    msg_info "Requesting Let's Encrypt certificate for ${domain}"

    certbot certonly --standalone \
        --non-interactive \
        --agree-tos \
        --email "admin@${domain}" \
        --domain "${domain}" \
        --cert-name aegis-waf

    local le_live="/etc/letsencrypt/live/aegis-waf"
    if [ -d "${le_live}" ]; then
        mkdir -p "${CERT_DIR}"
        cp "${le_live}/fullchain.pem" "${CERT_DIR}/server.crt"
        cp "${le_live}/privkey.pem"   "${CERT_DIR}/server.key"

        chmod 600 "${CERT_DIR}/server.key"
        chmod 644 "${CERT_DIR}/server.crt"

        if id "${SERVICE_USER}" &>/dev/null; then
            chown "${SERVICE_USER}:${SERVICE_GROUP}" "${CERT_DIR}/server.key" "${CERT_DIR}/server.crt"
        fi

        msg_ok "Let's Encrypt certificate installed"
    else
        msg_err "Let's Encrypt certificate was not created"
        return 1
    fi
}

# ─── Diffie-Hellman parameters ──────────────────────────────────────────────

generate_dhparam() {
    local dh_file="${CERT_DIR}/dhparam.pem"

    if [ -f "${dh_file}" ]; then
        msg_info "DH parameters already exist: ${dh_file}"
        return 0
    fi

    msg_info "Generating DH parameters (2048-bit, this may take a moment)..."
    openssl dhparam -out "${dh_file}" 2048 2>/dev/null

    chmod 644 "${dh_file}"
    if id "${SERVICE_USER}" &>/dev/null; then
        chown "${SERVICE_USER}:${SERVICE_GROUP}" "${dh_file}"
    fi

    msg_ok "DH parameters generated"
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    check_root
    check_prereqs

    echo ""
    echo -e "${BOLD}Aegis WAF — TLS Certificate Setup${NC}"
    echo ""

    echo "Choose certificate type:"
    echo "  1) Self-signed (development / testing)"
    echo "  2) Let's Encrypt via certbot (production)"
    echo ""
    read -r -p "  Option [1]: " choice
    choice="${choice:-1}"

    if [ "${choice}" = "2" ]; then
        read -r -p "  Enter domain name: " domain
        if [ -z "${domain}" ]; then
            msg_err "Domain name is required for Let's Encrypt."
            exit 1
        fi
        setup_letsencrypt "${domain}"
    else
        read -r -p "  Enter domain name [localhost]: " domain
        domain="${domain:-localhost}"
        generate_self_signed "${domain}"
    fi

    read -r -p "  Generate Diffie-Hellman parameters for forward secrecy? [Y/n]: " dh_choice
    if [[ ! "${dh_choice}" =~ ^[Nn]$ ]]; then
        generate_dhparam
    fi

    echo ""
    msg_ok "TLS setup complete."
}

main "$@"
