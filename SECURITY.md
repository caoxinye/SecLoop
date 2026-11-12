# Security Policy

## What this repository contains

SecLoop ships a **deliberately vulnerable** reference target and a **minimal
SQL injection probe**. Both exist solely to exercise the SecLoop feedback loop
end-to-end inside an isolated laboratory network. This is intentional and is the
whole point of the reference scenario.

Specifically, the repository contains:

- `target/webapp/` — a small web application that concatenates user input into
  SQL on purpose. It is **insecure by design**.
- `target/suricata/local.rules` — IDS rules that detect SQLi against that target.
- `battlefield/attacks/sqli_lab.py` — a time-based blind SQLi probe. It refuses
  any target outside the isolated lab network `192.168.57.0/24` and loopback
  (`ALLOWED_TARGET_NETS`), and its default target is the lab VM
  (`192.168.57.200`). Point it only at the lab.
- `vagrant/` — the Infrastructure-as-Code that builds the two-VM lab.

## What this repository does NOT contain

In line with responsible-research practice, we do **not** distribute the full
attack corpus used in the paper's evaluation, nor any weaponized exploit or
payload aimed at third-party systems. Providing such material would be
irresponsible. Only the single self-contained lab scenario described above is
included.

## Mandatory operating constraints

1. **Never expose the lab to the internet.** The lab network
   (`192.168.57.0/24`) must remain host-only / private. Do not bridge it to a
   production or corporate network.
2. **Run it only on systems you own or are explicitly authorized to test.**
3. The target VM is intentionally unhardened. Treat it as disposable: it should
   be destroyed rather than reused once an experiment ends.
4. The SQLi probe must not be repointed at any host you do not control.

## Antivirus / endpoint-protection notice

Some security tooling quarantines or blocks lab exploit scripts. If your
endpoint protection interferes with provisioning, add an exclusion **only for
the disposable lab VM directory**, never for your whole machine.

## Reporting a vulnerability

If you find a security issue in SecLoop's own code — for example a path that
escapes the lab network, a command-injection flaw in the SOC layer, a
credential leak, or a way the agent could invoke arbitrary commands outside the
intended environment — please report it privately rather than opening a public
issue. Include:

- affected file and version/commit,
- a minimal reproduction,
- the impact you believe it has.

We aim to acknowledge reports within a reasonable period and will credit
reporters who wish to be named.

## Scope note

SecLoop is a research prototype for security automation. It is **not** a
production hardening system and makes no claim to be. Do not deploy it on
systems that carry real traffic or real data.
