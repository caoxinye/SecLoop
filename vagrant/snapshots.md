# Initial snapshots (`kali_init` / `target_init`)

The SOC restores an initial snapshot after **every** round (`docs/INTERFACES.md`
§5, step 5): the blue VM is rolled back to `target_init` so the next round starts
from a clean, undefended state. `kali_init` is the equivalent clean point for the
attacker VM (the SOC does not have to restore it, but an operator does, e.g.
after a run that left iptables rules or extra files behind).

Both names are frozen by `docs/INTERFACES.md` §1. `BlueTeamController.restore_snapshot()`
derives them as `f"{vm}_init"` and **fails loudly** when the snapshot is missing
(`vagrant_driver.VagrantSnapshotError`) rather than warning and carrying on without a
rollback, which would let the next round measure a polluted VM.

## Re-take the snapshot after changing provisioning

A snapshot is a frozen copy of the guest, so **it also freezes the guest's
configuration**. If you change anything inside a VM and then re-run
`vagrant provision` — a provisioner fix, a new Apache vhost, an updated
`local.rules`, a corrected Suricata interface — the running VM is right but the
snapshot is still the old state, and the SOC rolls the VM back to it at the start
of every round.

The symptom is confusing: the change appears to have worked (you verify it
directly), then the very next round behaves like it was never applied — an empty
`fast.log` can come back after the Suricata capture interface was fixed and verified.

Re-take the affected snapshot:

```sh
SECLOOP_SNAPSHOT_FORCE=1 bash snapshots.sh target   # or: ... kali
```

`up.sh` gets the ordering right automatically, because it runs `snapshots.sh`
*after* `vagrant up` has finished provisioning. The trap only appears when you
provision by hand.

## Recommended: one command

```sh
cd vagrant
bash up.sh            # vagrant up --provider vmware_desktop + snapshots.sh
```

or, if the VMs are already up:

```sh
cd vagrant
bash snapshots.sh                 # creates kali_init and target_init
bash snapshots.sh target          # only the blue VM
SECLOOP_SNAPSHOT_FORCE=1 bash snapshots.sh   # delete + recreate existing snapshots
```

`snapshots.sh` is idempotent: an existing `<vm>_init` is skipped unless
`SECLOOP_SNAPSHOT_FORCE=1` is set, and any failure (VM not running, provider
refusing the snapshot) exits non-zero.

## Exact manual steps

Vagrant's snapshot CLI takes the machine name first (a two-VM environment cannot
use the implicit single-machine form):

```sh
cd vagrant

# 1. the VMs must be running
vagrant status
#    Expected: kali = running, target = running

# 2. create the snapshots (required before the SOC can roll a VM back)
vagrant snapshot save kali   kali_init
vagrant snapshot save target target_init

# 3. verify
vagrant snapshot list kali      # -> kali_init
vagrant snapshot list target    # -> target_init
```

On Windows, run the same commands from PowerShell or `cmd` (only `snapshots.sh`
itself needs a POSIX shell such as Git Bash or WSL).

### Automating it from `vagrant up`

A guest-side shell provisioner **cannot** create these snapshots: a VMware
snapshot is a host operation (`vmrun`), not something the guest can do. The
Vagrantfile therefore offers an opt-in host-side trigger:

```sh
SECLOOP_AUTO_SNAPSHOT=1 vagrant up --provider vmware_desktop
```

It is off by default because the trigger runs `vagrant snapshot save` while the
outer `vagrant up` still holds the environment lock; if that bites (Vagrant
reports that the environment is locked, or the trigger never finishes), just run
`bash snapshots.sh` afterwards. `up.sh` is the reliable automation path.

## Restoring by hand

```sh
vagrant snapshot restore target target_init     # blue VM -> clean, undefended state
vagrant snapshot restore kali   kali_init       # attacker VM -> pristine
```

`vagrant snapshot save` refuses to reuse an existing name, so delete first when you
want to re-baseline (`restore` does not create anything and has no such restriction):

```sh
vagrant snapshot delete target target_init
vagrant snapshot save   target target_init
```

## When to re-create them

* after changing anything under `target/**` or `battlefield/attacks/**` (the
  snapshots are the environment the SOC measures, so they must match the code);
* after `vagrant provision` (a re-provision changes the guest state);
* if `GET /health` or a round reports `snapshot 'target_init' does not exist`.

Re-baseline after re-provisioning:

```sh
cd vagrant
vagrant provision
SECLOOP_SNAPSHOT_FORCE=1 bash snapshots.sh
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `snapshot 'target_init' does not exist on target` in the SOC log | the snapshots were never created → `bash snapshots.sh` |
| `vmrun`/snapshot provider error | `vagrant-vmware-desktop` plugin missing, or the `VagrantVMware` service is not running |
| Snapshot created but the round still fails | the snapshot was taken *after* a defence was deployed; `SECLOOP_SNAPSHOT_FORCE=1 bash snapshots.sh` on a clean VM |
| `vagrant snapshot save` complains the environment is locked | a nested `vagrant` call (e.g. the opt-in trigger) → run `bash snapshots.sh` directly |
| Disk filling up | VMware snapshots chain; delete stale ones with `vagrant snapshot delete <vm> <name>` |
