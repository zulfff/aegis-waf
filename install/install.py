#!/usr/bin/env python3
"""
Aegis WAF - Python Auto-Installer
https://github.com/aegis-waf/aegis-waf

Cross-platform installer using only stdlib.
Provides the same capabilities as the bash installer.
"""

from __future__ import annotations

import grp
import os
import pwd
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional, Tuple


# ─── Constants ───────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

BIN_DIR = Path(os.environ.get("BIN_DIR", "/usr/local/bin"))
CONF_DIR = Path(os.environ.get("CONF_DIR", "/etc/aegis-waf"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/var/lib/aegis-waf"))
LOG_DIR = Path(os.environ.get("LOG_DIR", "/var/log/aegis-waf"))
RUN_DIR = Path(os.environ.get("RUN_DIR", "/var/run/aegis-waf"))
SHARE_DIR = Path(os.environ.get("SHARE_DIR", "/usr/share/aegis-waf"))

SERVICE_NAME = "aegis-waf"
SERVICE_USER = "aegis-waf"
SERVICE_GROUP = "aegis-waf"

BACKUP_DIR: Optional[Path] = None
_step_idx = 0


# ─── Color helpers ───────────────────────────────────────────────────────────

class Color:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    BOLD = "\033[1m"
    NC = "\033[0m"

    @staticmethod
    def supports_color() -> bool:
        if not sys.stdout.isatty():
            return False
        if os.environ.get("NO_COLOR"):
            return False
        return True

    @classmethod
    def _fmt(cls, color: str, prefix: str, *args) -> str:
        if cls.supports_color():
            return f"  {color}[{prefix}]{cls.NC}    {' '.join(map(str, args))}"
        return f"  [{prefix}]    {' '.join(map(str, args))}"


def msg_info(*args) -> None:
    print(Color._fmt(Color.BLUE, "INFO", *args))


def msg_ok(*args) -> None:
    print(Color._fmt(Color.GREEN, "OK", *args))


def msg_warn(*args) -> None:
    print(Color._fmt(Color.YELLOW, "WARN", *args))


def msg_err(*args) -> None:
    print(Color._fmt(Color.RED, "ERROR", *args), file=sys.stderr)


def step_header(title: str) -> None:
    global _step_idx
    _step_idx += 1
    sep = "─" * 50
    if Color.supports_color():
        print(f"\n{Color.CYAN}{Color.BOLD}── Step {_step_idx}: {title} {sep}{Color.NC}\n")
    else:
        print(f"\n── Step {_step_idx}: {title} {sep}\n")


# ─── Platform detection ──────────────────────────────────────────────────────

def detect_os() -> str:
    system = os.uname().sysname
    if system == "Linux":
        os_release = Path("/etc/os-release")
        if os_release.exists():
            content = os_release.read_text()
            for line in content.splitlines():
                if line.startswith("ID="):
                    return line.split("=", 1)[1].strip().strip('"')
        if Path("/etc/redhat-release").exists():
            return "rhel"
        return "linux-unknown"
    elif system == "Darwin":
        return "macos"
    return "unknown"


def detect_arch() -> str:
    arch = os.uname().machine
    mapping = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
        "armv7l": "armv7",
        "armhf": "armv7",
    }
    return mapping.get(arch, arch)


def detect_pkg_manager() -> str:
    os_id = detect_os()
    pkg_map = {
        "ubuntu": "apt", "debian": "apt", "linuxmint": "apt",
        "pop": "apt", "raspbian": "apt",
        "centos": "yum", "rhel": "yum", "rocky": "yum",
        "almalinux": "yum", "fedora": "dnf", "amzn": "yum",
        "opensuse-leap": "zypper", "opensuse-tumbleweed": "zypper", "sles": "zypper",
        "arch": "pacman", "manjaro": "pacman", "endeavouros": "pacman",
        "alpine": "apk",
        "macos": "brew",
    }
    return pkg_map.get(os_id, "unknown")


# ─── Shell helpers ───────────────────────────────────────────────────────────

def run(cmd, check: bool = True, capture: bool = False, **kwargs) -> subprocess.CompletedProcess:
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    if capture:
        return subprocess.run(cmd, check=check, text=True, capture_output=True, **kwargs)
    return subprocess.run(cmd, check=check, **kwargs)


def run_quiet(cmd) -> subprocess.CompletedProcess:
    try:
        return run(cmd, capture=True)
    except subprocess.CalledProcessError as e:
        return e


def user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def is_root() -> bool:
    return os.geteuid() == 0


# ─── Pre-flight checks ───────────────────────────────────────────────────────

def check_root() -> None:
    if not is_root():
        msg_err("This installer must be run as root (use sudo).")
        sys.exit(1)
    msg_ok("Running with root privileges")


def check_deps() -> None:
    missing = []
    for cmd in ("id", "uname", "mkdir", "chown", "chmod", "cp"):
        if shutil.which(cmd) is None:
            missing.append(cmd)
    if missing:
        msg_err(f"Missing required commands: {' '.join(missing)}")
        sys.exit(1)
    msg_ok("Required dependencies are available")


def check_existing() -> None:
    config = CONF_DIR / "aegis-waf.toml"
    if CONF_DIR.exists() and config.exists():
        msg_warn(f"Existing installation detected at {CONF_DIR}")
        try:
            confirm = input("  Overwrite and reinstall? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nInstallation aborted.")
            sys.exit(0)
        if confirm not in ("y", "yes"):
            print("Installation aborted.")
            sys.exit(0)


# ─── Rollback support ────────────────────────────────────────────────────────

def setup_rollback() -> None:
    global BACKUP_DIR
    BACKUP_DIR = Path(tempfile.mkdtemp(prefix="aegis-waf-backup."))
    msg_info(f"Backup directory: {BACKUP_DIR}")

    if CONF_DIR.exists():
        try:
            shutil.copytree(CONF_DIR, BACKUP_DIR / "aegis-waf.conf.bak")
        except OSError:
            pass
    if DATA_DIR.exists():
        try:
            shutil.copytree(DATA_DIR, BACKUP_DIR / "aegis-waf.data.bak")
        except OSError:
            pass
    msg_ok("Backup created")


def perform_rollback() -> None:
    print()
    msg_warn("Installation failed. Rolling back changes...")

    if BACKUP_DIR and BACKUP_DIR.exists():
        conf_bak = BACKUP_DIR / "aegis-waf.conf.bak"
        data_bak = BACKUP_DIR / "aegis-waf.data.bak"

        if conf_bak.exists():
            shutil.rmtree(CONF_DIR, ignore_errors=True)
            shutil.copytree(conf_bak, CONF_DIR)
        if data_bak.exists():
            shutil.rmtree(DATA_DIR, ignore_errors=True)
            shutil.copytree(data_bak, DATA_DIR)
        shutil.rmtree(BACKUP_DIR, ignore_errors=True)

    for cmd in (
        f"systemctl stop {SERVICE_NAME}",
        f"systemctl disable {SERVICE_NAME}",
    ):
        run_quiet(cmd)

    (Path("/etc/systemd/system") / f"{SERVICE_NAME}.service").unlink(missing_ok=True)
    (BIN_DIR / "aegis-waf").unlink(missing_ok=True)

    run_quiet("systemctl daemon-reload")
    msg_err("Rollback complete.")
    sys.exit(1)


# ─── System user / group ─────────────────────────────────────────────────────

def create_user() -> None:
    step_header("Creating system user and group")

    if user_exists(SERVICE_USER):
        msg_info(f"User '{SERVICE_USER}' already exists")
    else:
        if detect_os() == "macos":
            uid = _find_free_uid()
            for cmd in (
                f'dscl . -create "/Users/{SERVICE_USER}"',
                f'dscl . -create "/Users/{SERVICE_USER}" UserShell /usr/bin/false',
                f'dscl . -create "/Users/{SERVICE_USER}" UniqueID {uid}',
                f'dscl . -create "/Users/{SERVICE_USER}" PrimaryGroupID {uid}',
                f'dscl . -create "/Users/{SERVICE_USER}" NFSHomeDirectory /var/empty',
            ):
                run_quiet(cmd)
        else:
            for cmd in (
                f"useradd --system --no-create-home --shell /usr/sbin/nologin --home-dir /var/empty {SERVICE_USER}",
                f"useradd --system --no-create-home --shell /sbin/nologin --home-dir /var/empty {SERVICE_USER}",
            ):
                result = run_quiet(cmd)
                if result.returncode == 0:
                    break
        msg_ok(f"Created system user '{SERVICE_USER}'")

    if not group_exists(SERVICE_GROUP):
        if detect_os() == "macos":
            gid = _find_free_gid()
            run_quiet(f'dscl . -create "/Groups/{SERVICE_GROUP}"')
            run_quiet(f'dscl . -create "/Groups/{SERVICE_GROUP}" PrimaryGroupID {gid}')
        else:
            run_quiet(f"groupadd --system {SERVICE_GROUP}")
        msg_ok(f"Created system group '{SERVICE_GROUP}'")


def _find_free_uid() -> int:
    uid = 550
    while True:
        try:
            pwd.getpwuid(uid)
            uid += 1
        except KeyError:
            return uid


def _find_free_gid() -> int:
    gid = 550
    while True:
        try:
            grp.getgrgid(gid)
            gid += 1
        except KeyError:
            return gid


# ─── Directory setup ─────────────────────────────────────────────────────────

def setup_directories() -> None:
    step_header("Creating directory structure")

    for d in (CONF_DIR, DATA_DIR, LOG_DIR, RUN_DIR, SHARE_DIR):
        d.mkdir(parents=True, exist_ok=True)
        msg_info(f"Created {d}" if not d.exists() else f"Directory exists: {d}")  # no-op, just reporting
        shutil.chown(d, user=SERVICE_USER, group=SERVICE_GROUP)
        d.chmod(0o750)

    DATA_DIR.chmod(0o700)
    msg_ok("Directory structure ready")


# ─── Copy files ──────────────────────────────────────────────────────────────

def copy_binaries() -> None:
    step_header("Installing binaries")

    arch = detect_arch()
    src_binary = PROJECT_ROOT / "bin" / "aegis-waf"
    candidates = [
        src_binary,
        PROJECT_ROOT / "bin" / f"aegis-waf-{arch}",
    ]

    binary_path = None
    for candidate in candidates:
        if candidate.is_file():
            binary_path = candidate
            break

    if binary_path is None:
        msg_err(f"Binary not found — checked: {', '.join(str(c) for c in candidates)}")
        raise FileNotFoundError("No binary found")

    dest = BIN_DIR / "aegis-waf"
    shutil.copy2(binary_path, dest)
    shutil.chown(dest, user="root", group="root")
    dest.chmod(0o755)

    msg_ok(f"Binary installed to {dest}")


def copy_configs() -> None:
    step_header("Installing configuration files")

    src_config = PROJECT_ROOT / "install" / "config" / "default.toml"
    dest_config = CONF_DIR / "aegis-waf.toml"

    if src_config.is_file():
        if dest_config.exists():
            timestamp = time.strftime("%Y%m%d%H%M%S")
            shutil.copy2(dest_config, CONF_DIR / f"aegis-waf.toml.bak.{timestamp}")
            msg_info("Backed up existing config")
        shutil.copy2(src_config, dest_config)
        msg_ok(f"Configuration installed to {dest_config}")
    else:
        msg_warn(f"Default config not found at {src_config}, creating minimal config...")
        dest_config.write_text("""# Aegis WAF - Default Configuration (auto-generated)
[server]
listen_address = "0.0.0.0"
listen_port = 8443

[proxy]
backend = "http://127.0.0.1:8080"

[rate_limit]
enabled = true
requests_per_second = 100
burst = 200
""")

    shutil.chown(dest_config, user=SERVICE_USER, group=SERVICE_GROUP)
    dest_config.chmod(0o640)


# ─── Systemd service ─────────────────────────────────────────────────────────

def setup_systemd() -> None:
    step_header("Setting up systemd service")

    if detect_os() == "macos":
        msg_warn("systemd not available on macOS — skipping")
        return

    if shutil.which("systemctl") is None:
        msg_warn("systemctl not found — skipping systemd setup")
        return

    src_service = PROJECT_ROOT / "install" / "systemd" / "aegis-waf.service"
    dest_service = Path(f"/etc/systemd/system/{SERVICE_NAME}.service")

    if src_service.is_file():
        shutil.copy2(src_service, dest_service)
        dest_service.chmod(0o644)
    else:
        msg_warn("Service file not found, creating default...")
        service_content = f"""[Unit]
Description=Aegis WAF DDoS Protection
Documentation=https://github.com/aegis-waf/aegis-waf
After=network.target redis.service
Wants=network.target

[Service]
Type=notify
User={SERVICE_USER}
Group={SERVICE_GROUP}
ExecStart={BIN_DIR}/aegis-waf service start
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aegis-waf
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
PrivateTmp=yes
ReadWritePaths={DATA_DIR} {LOG_DIR} {RUN_DIR}
RuntimeDirectory=aegis-waf
RuntimeDirectoryMode=0750
LimitNOFILE=65536
LimitNPROC=4096
MemoryHigh=2G
MemoryMax=4G

[Install]
WantedBy=multi-user.target
"""
        dest_service.write_text(service_content)
        dest_service.chmod(0o644)

    run(["systemctl", "daemon-reload"])
    msg_ok("Systemd service installed")

    try:
        confirm = input("  Enable and start aegis-waf service now? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirm = "n"

    if confirm not in ("n", "no"):
        run_quiet(["systemctl", "enable", SERVICE_NAME])
        result = run_quiet(["systemctl", "start", SERVICE_NAME])
        if result.returncode != 0:
            msg_warn(f"Service start failed — check journalctl -u {SERVICE_NAME}")
        else:
            msg_ok("Service enabled and started")
    else:
        msg_info(f"Service installed but not enabled. Run: systemctl enable --now {SERVICE_NAME}")


# ─── TLS certificates ────────────────────────────────────────────────────────

def setup_tls() -> None:
    step_header("TLS certificate setup")

    tls_script = PROJECT_ROOT / "install" / "scripts" / "setup-tls.sh"

    try:
        confirm = input("  Set up TLS certificates? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirm = "n"

    if confirm in ("y", "yes"):
        if tls_script.is_file():
            run(["bash", str(tls_script), str(CONF_DIR)])
            msg_ok("TLS certificates configured")
        else:
            _generate_self_signed_cert()
    else:
        msg_info("Skipping TLS setup")


def _generate_self_signed_cert() -> None:
    msg_info("TLS setup script not found — generating self-signed cert")
    cert_dir = CONF_DIR / "tls"
    cert_dir.mkdir(parents=True, exist_ok=True)

    run([
        "openssl", "req", "-x509", "-nodes", "-days", "365",
        "-newkey", "rsa:4096",
        "-keyout", str(cert_dir / "server.key"),
        "-out", str(cert_dir / "server.crt"),
        "-subj", "/CN=AegisWAF-SelfSigned",
    ])

    (cert_dir / "server.key").chmod(0o600)
    (cert_dir / "server.crt").chmod(0o644)
    shutil.chown(cert_dir / "server.key", user=SERVICE_USER, group=SERVICE_GROUP)
    shutil.chown(cert_dir / "server.crt", user=SERVICE_USER, group=SERVICE_GROUP)
    msg_ok("Self-signed certificate generated")


# ─── Health check ────────────────────────────────────────────────────────────

def run_health_check() -> None:
    step_header("Running health check")

    time.sleep(2)

    health_script = PROJECT_ROOT / "install" / "scripts" / "health-check.sh"

    if health_script.is_file():
        result = run_quiet(["bash", str(health_script), str(CONF_DIR)])
        if result.returncode == 0:
            msg_ok("Health check PASSED")
        else:
            if result.stdout:
                print(result.stdout)
            msg_warn("Health check returned warnings — review logs")
    else:
        _inline_health_check()


def _inline_health_check() -> None:
    all_ok = True

    result = run_quiet(f"pgrep -f {BIN_DIR}/aegis-waf")
    if result.returncode == 0:
        msg_ok("Process is running")
    else:
        msg_warn("Process not detected (may not be started yet)")
        all_ok = False

    if (CONF_DIR / "aegis-waf.toml").exists():
        msg_ok("Configuration file exists")
    else:
        msg_err("Configuration file missing")
        all_ok = False

    cert_path = CONF_DIR / "tls" / "server.crt"
    if cert_path.exists():
        result = run_quiet(["openssl", "x509", "-in", str(cert_path), "-noout", "-checkend", "0"])
        if result.returncode == 0:
            msg_ok("TLS certificate is valid")
        else:
            msg_warn("TLS certificate expired or invalid")
    else:
        msg_info("No TLS certificate found")

    if not all_ok:
        msg_warn("Some checks failed — review above warnings")


# ─── Final summary ───────────────────────────────────────────────────────────

def print_summary() -> None:
    print()
    if Color.supports_color():
        print(f"{Color.GREEN}{Color.BOLD}╔══════════════════════════════════════════════════════════════╗{Color.NC}")
        print(f"{Color.GREEN}{Color.BOLD}║           Aegis WAF Installation Complete!                  ║{Color.NC}")
        print(f"{Color.GREEN}{Color.BOLD}╚══════════════════════════════════════════════════════════════╝{Color.NC}")
    else:
        print("==============================================================")
        print("           Aegis WAF Installation Complete!                  ")
        print("==============================================================")
    print()
    print(f"  Binary:     {BIN_DIR}/aegis-waf")
    print(f"  Config:     {CONF_DIR}/aegis-waf.toml")
    print(f"  Data:       {DATA_DIR}")
    print(f"  Logs:       {LOG_DIR}")
    print(f"  User:       {SERVICE_USER}")
    print()
    print("  Quick start:")
    print(f"    sudo systemctl start {SERVICE_NAME}")
    print(f"    sudo journalctl -u {SERVICE_NAME} -f")
    print("    curl -k https://localhost:8443")
    print()


# ─── Main ────────────────────────────────────────────────────────────────────

def main() -> None:
    if Color.supports_color():
        print(f"\n{Color.CYAN}{Color.BOLD} ═══════════════════════════════════════════════════════════════{Color.NC}")
        print(f"{Color.CYAN}{Color.BOLD}   Aegis WAF Installer v1.0.0{Color.NC}")
        print(f"{Color.CYAN}{Color.BOLD}   OS: {detect_os()} | Arch: {detect_arch()}{Color.NC}")
        print(f"{Color.CYAN}{Color.BOLD} ═══════════════════════════════════════════════════════════════{Color.NC}")
    else:
        print(f"\n═══════════════════════════════════════════════════════════════")
        print(f"   Aegis WAF Installer v1.0.0")
        print(f"   OS: {detect_os()} | Arch: {detect_arch()}")
        print(f"═══════════════════════════════════════════════════════════════")
    print()

    try:
        check_root()
        check_deps()
        check_existing()
        setup_rollback()

        create_user()
        setup_directories()
        copy_binaries()
        copy_configs()
        setup_tls()
        setup_systemd()
        run_health_check()
        print_summary()

        if BACKUP_DIR and BACKUP_DIR.exists():
            shutil.rmtree(BACKUP_DIR, ignore_errors=True)
    except Exception:
        perform_rollback()
        raise


if __name__ == "__main__":
    main()
