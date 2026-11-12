#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Kali (red team VM) provisioning for the SecLoop BATTLE-FIELD lab.
#
# Installs exactly what battlefield/attacks/sqli_lab.py needs -- Python 3 plus
# the `requests` package, nothing else -- and installs the attack script as
# ~/attacks/sqli_lab.py for user `vagrant`, which is the path the RTC uses:
#
#   cd ~/attacks && timeout --signal=TERM --kill-after=15 900 python3 sqli_lab.py --target-ip 192.168.57.200 ...
#
# The script arrives through the Vagrantfile's `file` provisioner at
# /tmp/secloop/sqli_lab.py (no file server, no network fetch).  Kali is a rolling
# release, so the install steps are idempotent and depend on nothing but apt.
#
# Idempotent: safe to re-run via `vagrant provision kali`. Fails loudly.

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

STAGE_DIR="${SECLOOP_STAGE_DIR:-/tmp/secloop}"
VAGRANT_USER="vagrant"
LOG_TAG="[attacker_setup]"

log() { printf '%s %s\n' "$LOG_TAG" "$*" >&2; }
die() { printf '%s ERROR: %s\n' "$LOG_TAG" "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (the Vagrant shell provisioner does)"

# --------------------------------------------------------------------------
# 0. preconditions
# --------------------------------------------------------------------------
command -v apt-get >/dev/null 2>&1 || die "apt-get not found; is this the kali box?"

VAGRANT_HOME="$(getent passwd "$VAGRANT_USER" | cut -d: -f6 || true)"
[ -n "${VAGRANT_HOME:-}" ] || die "user '$VAGRANT_USER' does not exist on this VM"
ATTACK_DIR="${SECLOOP_ATTACK_DIR:-${VAGRANT_HOME}/attacks}"

SRC_SCRIPT=""
if [ -f "${STAGE_DIR}/sqli_lab.py" ]; then
  SRC_SCRIPT="${STAGE_DIR}/sqli_lab.py"
else
  SRC_SCRIPT="$(find "$STAGE_DIR" -maxdepth 3 -type f -name 'sqli_lab.py' -print -quit 2>/dev/null || true)"
fi
[ -n "${SRC_SCRIPT:-}" ] && [ -f "$SRC_SCRIPT" ] \
  || die "battlefield/attacks/sqli_lab.py was not uploaded to ${STAGE_DIR}; check the 'file' provisioner for the kali VM"

# --------------------------------------------------------------------------
# 1. python3 + requests
# --------------------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  log "installing python3"
  apt-get update -y || die "apt-get update failed on kali"
  apt-get install -y --no-install-recommends python3 || die "cannot install python3"
fi
log "python: $(python3 --version 2>&1)"

if python3 -c 'import requests' >/dev/null 2>&1; then
  log "requests already present: $(python3 -c 'import requests; print(requests.__version__)')"
else
  log "installing requests (apt first, pip as fallback)"
  apt-get update -y || log "apt-get update failed; trying the install anyway"
  if apt-get install -y --no-install-recommends python3-requests; then
    :
  elif python3 -m pip install --break-system-packages requests; then
    :
  elif python3 -m pip install requests; then
    :
  else
    die "cannot install the 'requests' package (needed by sqli_lab.py)"
  fi
fi
python3 -c 'import requests' >/dev/null 2>&1 \
  || die "'requests' is still not importable after installation"
log "requests: $(python3 -c 'import requests; print(requests.__version__)')"

# --------------------------------------------------------------------------
# 2. install the attack script
# --------------------------------------------------------------------------
install -d -o "$VAGRANT_USER" -g "$VAGRANT_USER" -m 0755 "$ATTACK_DIR"
install -o "$VAGRANT_USER" -g "$VAGRANT_USER" -m 0755 "$SRC_SCRIPT" "${ATTACK_DIR}/sqli_lab.py"
log "installed ${ATTACK_DIR}/sqli_lab.py ($(wc -c <"${ATTACK_DIR}/sqli_lab.py") bytes)"

# syntax gate: never hand the SOC a script that cannot even be parsed
sudo -u "$VAGRANT_USER" python3 - "${ATTACK_DIR}/sqli_lab.py" <<'PY' || die "sqli_lab.py does not parse as Python"
import ast
import sys

path = sys.argv[1]
with open(path, "rb") as handle:
    ast.parse(handle.read(), filename=path)
print(f"ast.parse OK: {path}", file=sys.stderr)
PY

# informational only: the CLI contract itself is exercised end-to-end by the SOC
if sudo -u "$VAGRANT_USER" bash -lc "cd '${ATTACK_DIR}' && python3 sqli_lab.py --help >/dev/null 2>&1"; then
  log "sqli_lab.py --help OK"
else
  log "WARNING: sqli_lab.py --help did not exit 0; the SOC invocation is the real test"
fi

# --------------------------------------------------------------------------
# 3. the private (host-only) lab NIC
# --------------------------------------------------------------------------
# Vagrant's vmware_desktop provider configures the private network through its
# guest capability, which does NOT cover this Kali box: the NIC comes up with
# carrier, but NetworkManager just retries DHCP forever against a vmnet that has
# no DHCP server, so the guest ends up with no address on the lab network (the
# target VM, being Ubuntu, is configured correctly by the same step).  We
# therefore assign the contract address ourselves.
#
# The private NIC is the one that is NOT carrying the default route -- eth0 is
# the NAT interface and owns the default route.
LAB_IP="192.168.57.199"
LAB_PREFIX="24"
LAB_IFACE=""
for _path in /sys/class/net/*; do
  _name="$(basename "$_path")"
  [ "$_name" = "lo" ] && continue
  ip route show default 2>/dev/null | grep -q "dev ${_name}" && continue
  LAB_IFACE="$_name"
  break
done

if [ -z "$LAB_IFACE" ]; then
  log "WARNING: no private-network NIC found; the lab network will not work"
elif ip -4 addr show "$LAB_IFACE" 2>/dev/null | grep -q "${LAB_IP}/"; then
  log "lab NIC already configured: ${LAB_IFACE} = ${LAB_IP}/${LAB_PREFIX}"
else
  log "configuring ${LAB_IFACE} as ${LAB_IP}/${LAB_PREFIX} (private lab network)"
  if command -v nmcli >/dev/null 2>&1; then
    timeout 30 nmcli con delete secloop-lab >/dev/null 2>&1 || true
    # ipv4.never-default keeps this NIC from stealing the default route.
    if timeout 40 nmcli con add type ethernet con-name secloop-lab \
           ifname "$LAB_IFACE" ipv4.method manual \
           ipv4.addresses "${LAB_IP}/${LAB_PREFIX}" ipv4.never-default yes \
         && timeout 40 nmcli con up secloop-lab; then
      log "nmcli: secloop-lab is up on ${LAB_IFACE}"
    else
      log "WARNING: nmcli could not configure ${LAB_IFACE}; falling back to iproute2"
      ip addr add "${LAB_IP}/${LAB_PREFIX}" dev "$LAB_IFACE" 2>/dev/null || true
      ip link set "$LAB_IFACE" up || true
    fi
  else
    ip addr add "${LAB_IP}/${LAB_PREFIX}" dev "$LAB_IFACE" 2>/dev/null || true
    ip link set "$LAB_IFACE" up || true
  fi
fi

if ip -4 addr show "$LAB_IFACE" 2>/dev/null | grep -q "${LAB_IP}/"; then
  log "lab NIC OK: ${LAB_IFACE} = ${LAB_IP}/${LAB_PREFIX}"
else
  log "WARNING: ${LAB_IFACE:-<none>} has no ${LAB_IP}; the attack stage will fail"
fi

# --------------------------------------------------------------------------
# 4. record what was provisioned (handy inside the guest)
# --------------------------------------------------------------------------
install -d -m 0755 /etc/secloop
cat >/etc/secloop/attacker.json <<EOF
{
  "role": "red",
  "user": "${VAGRANT_USER}",
  "attack_dir": "${ATTACK_DIR}",
  "script": "${ATTACK_DIR}/sqli_lab.py",
  "python": "$(python3 --version 2>&1)",
  "requests": "$(python3 -c 'import requests; print(requests.__version__)')"
}
EOF

log "PROVISION OK: ${ATTACK_DIR}/sqli_lab.py ready for '${VAGRANT_USER}'"
log "NOTE: the kali_init snapshot is created from the host (see vagrant/snapshots.md)"
