#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# One-command bring-up of the SecLoop BATTLE-FIELD lab:
#
#   bash up.sh                      # up + initial snapshots
#   bash up.sh --provision          # force a re-provision
#
# Equivalent to:
#   vagrant up --provider vmware_desktop   # real provisioning (see provision/*.sh)
#   bash snapshots.sh                      # kali_init / target_init
#
# After this returns, start the SOC:
#   python ../battlefield/soc_server.py

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

command -v vagrant >/dev/null 2>&1 || {
  printf 'ERROR: the vagrant executable is not on PATH\n' >&2
  exit 1
}

printf '==> vagrant up --provider vmware_desktop (first run downloads ~6 GB of boxes)\n'
vagrant up --provider vmware_desktop "$@"

printf '\n==> creating the initial snapshots the SOC restores\n'
bash snapshots.sh

cat <<'EOF'

Lab is up. Next:

  python ../battlefield/soc_server.py
  curl -s http://127.0.0.1:8988/health

Target liveness anchor : http://192.168.57.200/index.php   ("SecLoop target OK")
Vulnerable endpoint    : http://192.168.57.200/search.php?id=<id>
Attacker VM            : 192.168.57.199  (attack script at ~/attacks/sqli_lab.py)

Keep this network isolated: the target is deliberately vulnerable.
EOF
