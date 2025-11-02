#!/usr/bin/env bash
# dumpcap-orchestrator.sh
# Idempotent orchestrator for a robust dumpcap@<iface>.service with rotation & retention.
# Includes shell-wrapped ExecStart to safely handle optional FILTER/DURATION.

set -euo pipefail

#=============================#
# Defaults (override by flags)
#=============================#
IFACE=""
CAP_PATH=""
SERVICE_USER="root"
CAP_GROUP="wireshark"
CAP_DIR="/var/pcaps"
ENV_DIR="/etc/dumpcap.d"
UNIT_PATH="/etc/systemd/system/dumpcap@.service"
RETENTION_DAYS="14"
SNAPLEN="0"
BUFFER_MB="16"
FILESIZE_MB="1024"   # MB per file (~1 GiB)
FILES_KEEP="24"      # files in ring
DURATION_SEC=""      # optional
FILTER=""            # optional
DRY_RUN="0"
SETCAP_AUTO="1"
APPLY_TMPFILES="1"
ENABLE_START="1"

# Convenience actions
ACTION=""            # setup|uninstall|start|stop|restart|status|enable|disable|stop-all|purge

usage() {
cat <<EOF
Usage: sudo $0 --iface IFACE [options] [--action ACTION]

Core:
  --iface IFACE                 Interface to capture (e.g., eth0, any)

Rotation:
  --filesize-mb N               Per-file size MB (default ${FILESIZE_MB})
  --files N                     Files to keep (default ${FILES_KEEP})
  --duration-sec N              Also rotate every N seconds (optional)

Capture params:
  --snaplen N                   0=full packet (default ${SNAPLEN})
  --buffer-mb N                 OS capture buffer MB (default ${BUFFER_MB})
  --filter 'BPF expr'           e.g. 'vlan and tcp port 6500'

Paths/identity:
  --cap-dir PATH                Capture dir (default ${CAP_DIR})
  --env-dir PATH                Env dir (default ${ENV_DIR})
  --cap-group GROUP             Group owning captures (default ${CAP_GROUP})
  --service-user USER           Systemd User= (default ${SERVICE_USER})

Retention:
  --retention-days N            tmpfiles purge age (default ${RETENTION_DAYS})
  --no-apply-tmpfiles           Do not run tmpfiles immediately

Behavior:
  --no-setcap                   Skip setcap on /usr/bin/dumpcap
  --no-enable-start             Do not enable/start after setup
  --dry-run                     Print actions only

Actions (optional):
  --action setup|uninstall|start|stop|restart|status|enable|disable|stop-all|purge

Examples:
  $0 --iface eth0                                       # 1 GiB x24, keep 14d
  $0 --iface any --filesize-mb 256 --files 200 --duration-sec 900
  $0 --iface wlp7s0 --snaplen 256 --filter 'tcp port 6500'
  $0 --iface eth0 --action stop                         # stop service
  $0 --iface eth0 --action uninstall                    # remove unit/env/tmpfiles (keeps pcaps)
  $0 --iface any --action purge                         # stop-all + delete unit/env/tmpfiles + pcap dir
EOF
}

#-------------------------#
# Parse flags
#-------------------------#
while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface) IFACE="$2"; shift 2;;
    --filesize-mb) FILESIZE_MB="$2"; shift 2;;
    --files) FILES_KEEP="$2"; shift 2;;
    --duration-sec) DURATION_SEC="$2"; shift 2;;
    --snaplen) SNAPLEN="$2"; shift 2;;
    --buffer-mb) BUFFER_MB="$2"; shift 2;;
    --filter) FILTER="$2"; shift 2;;
    --cap-dir) CAP_DIR="$2"; shift 2;;
    --env-dir) ENV_DIR="$2"; shift 2;;
    --cap-group) CAP_GROUP="$2"; shift 2;;
    --service-user) SERVICE_USER="$2"; shift 2;;
    --retention-days) RETENTION_DAYS="$2"; shift 2;;
    --no-apply-tmpfiles) APPLY_TMPFILES="0"; shift 1;;
    --no-setcap) SETCAP_AUTO="0"; shift 1;;
    --no-enable-start) ENABLE_START="0"; shift 1;;
    --dry-run) DRY_RUN="1"; shift 1;;
    --action) ACTION="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1"; usage; exit 1;;
  esac
done

require_root() { [[ "$(id -u)" -eq 0 ]] || { echo "ERROR: run as root"; exit 1; }; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing '$1'"; exit 1; }; }
run() { [[ "$DRY_RUN" == "1" ]] && echo "[DRY] $*" || { echo "+ $*"; eval "$@"; }; }

require_root
need_cmd systemctl
need_cmd tee
need_cmd mkdir
need_cmd chgrp
need_cmd chmod

#-------------------------#
# Helpers
#-------------------------#
install_dumpcap_if_missing() {
  if ! command -v dumpcap >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      run "apt-get update"
      run "DEBIAN_FRONTEND=noninteractive apt-get install -y wireshark-common"
    elif command -v dnf >/dev/null 2>&1; then
      run "dnf install -y wireshark-cli"
    else
      echo "ERROR: Unknown package manager. Install Wireshark CLI manually."; exit 1
    fi
  fi
  CAP_PATH="$(command -v dumpcap)"
}

ensure_group_and_dirs() {
  getent group "${CAP_GROUP}" >/dev/null 2>&1 || run "groupadd ${CAP_GROUP}"
  run "mkdir -p ${CAP_DIR}"
  run "chgrp ${CAP_GROUP} ${CAP_DIR}"
  run "chmod 2750 ${CAP_DIR}"
  run "mkdir -p ${ENV_DIR}"
  run "chmod 755 ${ENV_DIR}"
}

apply_setcap() {
  [[ "$SETCAP_AUTO" == "1" ]] || return 0
  need_cmd setcap
  install_dumpcap_if_missing
  run "setcap cap_net_raw,cap_net_admin+eip ${CAP_PATH}"
}

write_tmpfiles_rule() {
  local rule="/etc/tmpfiles.d/pcaps.conf"
  local content="d ${CAP_DIR} 2750 root ${CAP_GROUP} ${RETENTION_DAYS}d"
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[DRY] write ${rule}: ${content}"
  else
    echo "${content}" | tee "${rule}" >/dev/null
  fi
  if [[ "$APPLY_TMPFILES" == "1" ]]; then
    need_cmd systemd-tmpfiles
    run "systemd-tmpfiles --create ${rule}"
  fi
}

write_env_file() {
  [[ -z "$IFACE" ]] && { echo "ERROR: --iface is required"; exit 1; }
  local env_file="${ENV_DIR}/${IFACE}.env"
  # Always emit all variables (empty or not) to avoid systemd warnings
  {
    echo "# Generated by dumpcap-orchestrator.sh"
    echo "SNAPLEN=${SNAPLEN}"
    echo "BUFFER_MB=${BUFFER_MB}"
    echo "FILTER=${FILTER}"
    echo "DURATION=${DURATION_SEC}"
  } | ( [[ "$DRY_RUN" == "1" ]] && cat || tee "${env_file}" >/dev/null )
  [[ "$DRY_RUN" == "1" ]] || { run "chmod 640 ${env_file}"; run "chgrp ${CAP_GROUP} ${env_file}"; }
}

write_unit_file() {
  local filesize_kb=$(( FILESIZE_MB * 1024 ))
  local unit_content
  read -r -d '' unit_content <<'UNIT' || true
[Unit]
Description=Continuous packet capture (pcapng) on interface %I with dumpcap
Documentation=man:dumpcap(1)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=__SERVICE_USER__
Group=__CAP_GROUP__

EnvironmentFile=-/etc/dumpcap.d/%I.env
Environment=SNAPLEN=0
Environment=BUFFER_MB=16
Environment=FILTER=
Environment=DURATION=
Environment=FILESIZE_KB=__FILESIZE_KB__
Environment=FILES_KEEP=__FILES_KEEP__
Environment=CAP_DIR=__CAP_DIR__

# Shell-wrapped ExecStart: safely handles optional FILTER/DURATION
ExecStart=/bin/sh -ec '\
  set -e; \
  args="-i %I -q -s ${SNAPLEN} -B ${BUFFER_MB} -b filesize:${FILESIZE_KB} -b files:${FILES_KEEP}"; \
  [ -n "${DURATION:-}" ] && args="$args -b duration:${DURATION}"; \
  [ -n "${FILTER:-}" ] && args="$args -f \"${FILTER}\""; \
  exec /usr/bin/dumpcap $args -w ${CAP_DIR}/%I-%%Y%%m%%d-%%H%%M%%S.pcapng \
'

NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictNamespaces=yes
ReadWritePaths=__CAP_DIR__
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

Restart=always
RestartSec=2s

[Install]
WantedBy=multi-user.target
UNIT

  unit_content="${unit_content//__SERVICE_USER__/${SERVICE_USER}}"
  unit_content="${unit_content//__CAP_GROUP__/${CAP_GROUP}}"
  unit_content="${unit_content//__FILESIZE_KB__/${filesize_kb}}"
  unit_content="${unit_content//__FILES_KEEP__/${FILES_KEEP}}"
  unit_content="${unit_content//__DURATION__/${DURATION_SEC}}"
  unit_content="${unit_content//__CAP_DIR__/${CAP_DIR}}"

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[DRY] write ${UNIT_PATH} with:"
    echo "${unit_content}"
  else
    echo "${unit_content}" | tee "${UNIT_PATH}" >/dev/null
    run "systemctl daemon-reload"
  fi
}

do_setup() {
  [[ -z "$IFACE" ]] && { echo "ERROR: --iface is required"; exit 1; }
  install_dumpcap_if_missing
  ensure_group_and_dirs
  apply_setcap
  write_tmpfiles_rule
  write_env_file
  write_unit_file
  if [[ "$ENABLE_START" == "1" ]]; then
    run "systemctl enable --now dumpcap@${IFACE}.service"
    run "systemctl status --no-pager dumpcap@${IFACE}.service || true"
  else
    echo "Unit installed. Enable/start with: systemctl enable --now dumpcap@${IFACE}.service"
  fi
  echo "Captures in: ${CAP_DIR}"
}

do_uninstall() {
  [[ -z "$IFACE" ]] && { echo "ERROR: --iface is required"; exit 1; }
  run "systemctl stop dumpcap@${IFACE}.service || true"
  run "systemctl disable dumpcap@${IFACE}.service || true"
  run "rm -f ${ENV_DIR}/${IFACE}.env || true"
  run "rm -f /etc/tmpfiles.d/pcaps.conf || true"
  run "systemctl daemon-reload"
  echo "Uninstalled for ${IFACE}. (pcaps preserved in ${CAP_DIR})"
}

do_purge() {
  # stop everything and remove all artifacts + pcap dir
  run "systemctl stop 'dumpcap@*' || true"
  run "systemctl disable 'dumpcap@*' || true"
  run "rm -f ${UNIT_PATH} || true"
  run "rm -rf ${ENV_DIR} || true"
  run "rm -f /etc/tmpfiles.d/pcaps.conf || true"
  run "rm -rf ${CAP_DIR} || true"
  run "systemctl daemon-reload"
  echo "Purged unit, env, tmpfiles, and capture directory."
}

#-------------------------#
# Action dispatcher
#-------------------------#
case "${ACTION:-setup}" in
  setup)     do_setup ;;
  uninstall) do_uninstall ;;
  start)     [[ -z "$IFACE" ]] && { echo "ERROR: --iface required"; exit 1; }
             run "systemctl start dumpcap@${IFACE}.service" ;;
  stop)      [[ -z "$IFACE" ]] && { echo "ERROR: --iface required"; exit 1; }
             run "systemctl stop dumpcap@${IFACE}.service" ;;
  restart)   [[ -z "$IFACE" ]] && { echo "ERROR: --iface required"; exit 1; }
             run "systemctl restart dumpcap@${IFACE}.service" ;;
  status)    [[ -z "$IFACE" ]] && { echo "ERROR: --iface required"; exit 1; }
             run "systemctl status --no-pager dumpcap@${IFACE}.service || true" ;;
  enable)    [[ -z "$IFACE" ]] && { echo "ERROR: --iface required"; exit 1; }
             run "systemctl enable --now dumpcap@${IFACE}.service" ;;
  disable)   [[ -z "$IFACE" ]] && { echo "ERROR: --iface required"; exit 1; }
             run "systemctl disable dumpcap@${IFACE}.service" ;;
  stop-all)  run "systemctl stop 'dumpcap@*' || true" ;;
  purge)     do_purge ;;
  *)         echo "Unknown --action '${ACTION}'. See --help."; exit 1 ;;
esac
