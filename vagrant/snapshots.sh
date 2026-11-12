#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Create the initial snapshots the SOC restores (docs/INTERFACES.md section 1).
#
#   bash snapshots.sh                 # kali + target -> kali_init / target_init
#   bash snapshots.sh target          # one machine
#   SECLOOP_SNAPSHOT_FORCE=1 bash snapshots.sh    # delete + recreate existing ones
#
# Run this from the Vagrant root (the directory holding the Vagrantfile) or from
# anywhere -- the script cd's to its own directory first.
#
# Why a host-side script instead of a guest provisioner: a VMware snapshot is a
# host operation (`vmrun`), so a shell provisioner running inside the VM cannot
# create it.  `vagrant/up.sh` runs this automatically after `vagrant up`; setting
# SECLOOP_AUTO_SNAPSHOT=1 additionally tries it from a Vagrant `after :up`
# trigger (off by default because a nested vagrant command runs under the same
# environment lock as the outer `vagrant up`).

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

VMS=("$@")
if [ "${#VMS[@]}" -eq 0 ]; then
  VMS=(kali target)
fi
FORCE="${SECLOOP_SNAPSHOT_FORCE:-0}"

command -v vagrant >/dev/null 2>&1 || {
  printf 'ERROR: the vagrant executable is not on PATH\n' >&2
  exit 1
}

list_snapshots() {
  local vm="$1"
  # `vagrant snapshot list <vm>` prints one name per line, sometimes indented and
  # sometimes prefixed with '*' for the active snapshot; normalise before matching.
  vagrant snapshot list "$vm" 2>/dev/null | tr -d '\r' | sed -e 's/^[[:space:]*]*//' -e 's/[[:space:]]*$//' || true
}

rc=0
for vm in "${VMS[@]}"; do
  name="${vm}_init"
  existing="$(list_snapshots "$vm")"
  if printf '%s\n' "$existing" | grep -qx -- "$name"; then
    if [ "$FORCE" = "1" ]; then
      printf 'deleting existing snapshot %s on %s\n' "$name" "$vm"
      vagrant snapshot delete "$vm" "$name" || { printf 'ERROR: could not delete %s on %s\n' "$name" "$vm" >&2; rc=1; continue; }
    else
      printf 'skip: snapshot %s already exists on %s (SECLOOP_SNAPSHOT_FORCE=1 to recreate)\n' "$name" "$vm"
      continue
    fi
  fi
  printf 'creating snapshot %s on %s ...\n' "$name" "$vm"
  if vagrant snapshot save "$vm" "$name"; then
    printf 'created %s on %s\n' "$name" "$vm"
  else
    printf 'ERROR: failed to create %s on %s (is the VM up? `vagrant status`)\n' "$name" "$vm" >&2
    rc=1
  fi
done

if [ "$rc" -eq 0 ]; then
  printf '\nSnapshots ready. The SOC restores <blue_vm>_init after every round.\n'
  printf 'Verify with: vagrant snapshot list target  /  vagrant snapshot list kali\n'
fi
exit "$rc"
