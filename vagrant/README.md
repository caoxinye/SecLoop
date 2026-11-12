# `vagrant/` — the BATTLE-FIELD lab (2 VMs, VMware)

This is the **only** reference environment shipped with SecLoop. It is a real
Vagrant environment: real boxes, real provisioning (Apache + PHP 7.2 + MySQL +
Suricata on the target, Python 3 + `requests` + the attack script on the
attacker), no simulation and no synthetic alerts.

| | red / attacker | blue / defender |
|---|---|---|
| VM name | `kali` | `target` |
| Box | `kalilinux/rolling` | `bento/ubuntu-18.04` |
| IP (private network) | `192.168.57.199` | `192.168.57.200` |
| Memory / vCPU | 2048 MB / 2 | 4096 MB / 2 |
| Installed | Python 3 + `requests`, `~/attacks/sqli_lab.py` | Apache + PHP 7.2 + MySQL, the vulnerable web app, Suricata + `local.rules` |
| Role in the loop | `RTC.run_attack()` — the attack sequence | `BTC.deploy_strategy()` and the `rs_service` probe |

All values come from `docs/INTERFACES.md` §1 and are mirrored by
`battlefield/soc/iac_generator.py`.

## Requirements (host)

* VMware Workstation Pro (or Player with the VMware Desktop provider) + the
  `vagrant-vmware-desktop` plugin and the `VagrantVMware` service running;
* Vagrant ≥ 2.2 (the paper's environment used 2.4.3);
* `VAGRANT_HOME` exported if the plugin and boxes were installed somewhere other
  than the default `~/.vagrant.d` (this lab uses `D:\vagrant.d`). Without it Vagrant
  cannot see `vagrant-vmware-desktop` at all and reports
  `The provider 'vmware_desktop' could not be found ... Vagrant knows about the
  following providers: docker, hyperv, virtualbox` — which reads like a missing
  plugin but is a missing environment variable. `vagrant status` does **not** accept
  `--provider`, so exporting the variable is the only fix.
* ~6 GB of free disk for the two boxes on first run, and a host that can host a
  `192.168.57.0/24` private network on a host-only vmnet (this repository's lab
  uses **VMnet4**; the specific number is whatever Virtual Network Editor assigned
  to a host-only adapter, not necessarily `VMnet8`, which is normally the NAT one).

**Keep this network isolated.** The target is deliberately vulnerable and the
SOC endpoint executes commands on these VMs; never bridge the lab to a
production or public network (see `SECURITY.md`).

## Quick start

```sh
cd vagrant
bash up.sh                    # vagrant up --provider vmware_desktop + snapshots.sh
python ../battlefield/soc_server.py
curl -s http://127.0.0.1:8988/health
```

Or step by step:

```sh
cd vagrant
vagrant up --provider vmware_desktop
vagrant snapshot save kali kali_init
vagrant snapshot save target target_init
python ../battlefield/soc_server.py
```

Then run one closed-loop round:

```sh
curl -s -X POST http://127.0.0.1:8988/execute_ability \
  -H 'Content-Type: application/json' \
  -d '{"strategy":[{"tool":"block_ip","params":{"ip":"192.168.57.199"}}],"attack_mode":"sqli"}'
```

## What provisioning does

Files reach the guests through explicit `file` provisioners (upload to
`/tmp/secloop`, then move into place with the shell provisioner) — Vagrant's
documented pattern. There is no file server, no download URL and no shared
folder, so provisioning also works on a Windows host where guest tools are not
installed.

`provision/attacker_setup.sh`

* installs Python 3 and `requests` (apt first, pip as fallback for Kali's
  PEP-668 managed environment);
* installs `battlefield/attacks/sqli_lab.py` as `~/attacks/sqli_lab.py` for user
  `vagrant`, `ast.parse`-checked so the SOC never receives an unparsable script;
* idempotent, fails loudly.

`provision/target_setup.sh`

* **bionic EOL fallback**: if `apt update` fails, rewrites the apt sources to
  `old-releases.ubuntu.com` (with `Acquire::Check-Valid-Until=false`) and retries;
* Apache 2 + **PHP 7.2 from bionic's own archive** (no third-party PPA -- the
  `ppa:ondrej/php` bionic pocket is empty, see `provision/target_setup.sh`) +
  MySQL 5.7;
* creates the lab database/user from `target/webapp/db.env` when present
  (otherwise the documented defaults) and imports `target/webapp/schema.sql`;
* deploys `target/webapp/*.php` into `/var/www/html` (never `db.env`), removes
  Apache's default `index.html`, and verifies `index.php` answers `200` with the
  marker `SecLoop target OK`;
* Suricata (`ppa:oisf/suricata-stable`): installs `target/suricata/local.rules`
  into the directory Suricata actually reads (`default-rule-path`, which on
  Debian packaging is usually `/var/lib/suricata/rules`), points `HOME_NET` at
  the lab network, sets the `af-packet` interface, keeps any ET Open rule files
  that exist, then runs `suricata -T` (**fails loudly with the parser output if a
  rule is rejected**) and restarts + verifies the service;
* writes `/etc/secloop/target.json` with everything it configured.

`suricata-update` (ET Open) is best effort: offline is not fatal, because the
lab's detection comes from `target/suricata/local.rules`.

## Snapshots

`kali_init` / `target_init` are required for the SOC to roll the environment back
after each round. They are created from the host (`snapshots.sh` / `up.sh`); a
guest provisioner cannot do it. See [snapshots.md](snapshots.md) for the exact
steps, the opt-in `SECLOOP_AUTO_SNAPSHOT=1` trigger, and troubleshooting.

## Extra VM pairs (parallel rounds)

`SOAR_VM_POOL` (JSON, `docs/INTERFACES.md` §3.3) lets the SOC use more than one
pair; the default is the single `kali`/`target` pair above. To describe another
pair, either add machines to this Vagrantfile or render a fresh environment:

```sh
python -m battlefield.soc.iac_generator --attack-mode sqli --output-dir <dir>
cd <dir>/env_sqli && vagrant up --provider vmware_desktop
SOAR_VAGRANT_ROOT=<dir>/env_sqli python battlefield/soc_server.py
```

(`battlefield.soc.iac_generator`, dotted, and run from the repository root. The path
form `battlefield/soc/iac_generator` is not a module, and `soc.iac_generator` only
resolves from inside `battlefield/`; both raise `ModuleNotFoundError`.)

The generator only *writes* a Vagrantfile — it never starts a VM, and the SOC
server never calls it (see the module docstring for why).

## Files

| File | Purpose |
|---|---|
| `Vagrantfile` | the two VMs, IPs, provider, provisioning |
| `up.sh` | `vagrant up` + snapshot creation in one command |
| `snapshots.sh` | create/verify `kali_init` / `target_init` (idempotent) |
| `snapshots.md` | exact snapshot steps, automation, troubleshooting |
| `provision/attacker_setup.sh` | Kali: Python 3 + `requests` + the attack script |
| `provision/target_setup.sh` | Ubuntu 18.04: LAMP + web app + Suricata + rules |
