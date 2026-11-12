<!-- SPDX-License-Identifier: Apache-2.0 -->

# SecLoop lab IDS rules

`local.rules` holds ten Suricata signatures (`sid:1000001`–`sid:1000010`) that
detect SQL-injection attempts in HTTP **requests** against the deliberately
vulnerable lab target. They are environment configuration for the reference
scenario, not a claim about production coverage.

Nothing in this repository writes alerts. Every line of `fast.log` must be
produced by Suricata actually observing the lab traffic; the summarizer in
`ids/combine_ids_log.py` consumes that file read-only.

## What the rules cover

| sid | tactic detected | matches |
|---|---|---|
| 1000001 | time-based blind via `SLEEP()` | `sleep(` |
| 1000002 | time-based blind via `BENCHMARK()` | `benchmark(` |
| 1000003 | schema metadata enumeration | `information_schema` |
| 1000004 | `UNION SELECT` | `union` … `select` within 16 bytes |
| 1000005 | conditional blind predicate | `and` … `if(` within 8 bytes |
| 1000006 | blind character extraction | `ascii(` … `substr(` within 32 bytes |
| 1000007 | literal break-out + comment | `'` … `--` within 512 bytes |
| 1000008 | quoted tautology | `or '1'='1` |
| 1000009 | numeric tautology | `or 1=1` |
| 1000010 | error-based extraction | `extractvalue(` |

Three deliberate choices:

* **No `$HOME_NET` / `$EXTERNAL_NET` variable.** The lab traffic goes from
  `192.168.57.199` to `192.168.57.200`, i.e. *inside* the usual HOME_NET
  definition; a rule spelled `-> $EXTERNAL_NET` would silently never match. Every
  rule therefore uses `alert http any any -> any any` with
  `flow:to_server,established`. To pin the file to the target host instead,
  replace the address pair with `any any -> 192.168.57.200 any`.
* **Only the request line is inspected** (`http_uri`), so the file works whether
  or not Suricata is also parsing response bodies.
* **Percent-encoding tolerant pairs.** The reference probe sends
  `id=1'%20AND%20IF(...,SLEEP(2),0)--%20-`; `SLEEP(`, `ASCII(SUBSTR(` and
  `information_schema` survive encoding, whereas raw spaces become `%20`.
  Rules 1000004/1000005/1000006 use `distance`/`within` so both the raw and the
  encoded spelling match.

Every `msg` begins with `SQL Injection Attempt - ` so `ids/combine_ids_log.py`
collapses the ten variants into one alert episode while listing the variants
individually.

## Load the rules on the target VM

```bash
# 1. install the file (the lab provisioner does this automatically)
sudo install -m 0644 local.rules /etc/suricata/rules/local.rules

# 2. make Suricata read it: /etc/suricata/suricata.yaml
#      default-rule-path: /var/lib/suricata/rules
#      rule-files:
#        - suricata.rules        # ET Open, if installed -- see below
#        - /etc/suricata/rules/local.rules
#    (an absolute path in rule-files is accepted; a bare filename is resolved
#     against default-rule-path, so keep the path explicit if in doubt)

# 3. validate before restarting -- this is the gate that must pass
sudo suricata -T -c /etc/suricata/suricata.yaml -v
#    expect a final line like:
#      <timestamp> - <Info> - Configuration provided was successfully loaded.
#                            10 rules successfully loaded, 0 rules failed
#    and no per-sid error for 1000001..1000010.

# 4. reload / restart and confirm alerts appear while the probe runs
sudo systemctl restart suricata
sudo tail -n 50 -f /var/log/suricata/fast.log
```

Since a bare `rule-files: - local.rules` entry is resolved under
`default-rule-path`, the two unambiguous spellings are:

```yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - /etc/suricata/rules/local.rules
```

## Verify that alerts are real

```bash
# with the probe running on the attacker VM:
python3 battlefield/attacks/sqli_lab.py --target-ip 192.168.57.200
# on the target VM, during/after the run:
sudo grep -c 'SQL Injection Attempt' /var/log/suricata/fast.log
sudo grep 'sid:1000001' /var/log/suricata/fast.log | head
```

Then feed the *real* log to the summarizer:

```bash
python3 ids/combine_ids_log.py --fastlog /var/log/suricata/fast.log --window-s 300
```

If `suricata -T` reports a failed rule, the message names the sid; fix the rule
rather than deleting it, and re-run `suricata -T`. If detection is silent while
`fast.log` is empty, check in order: (1) Suricata sees the lab interface
(`suricata --build-info`, `af-packet` section of `suricata.yaml`), (2) the
`rule-files` entry above is actually loaded (`sudo suricata -T ... -v` prints the
count), (3) the probe reached the target at all (the probe's own stderr).

## Additionally enabling ET Open

Our ten rules are intentionally narrow. ET Open adds broad SQLi, scanner and
protocol coverage, and is the recommended complement:

```bash
# suricata-update ships with Suricata >= 5; on older images install it via pip
sudo apt-get install -y python3-suricata-update   # or: sudo pip3 install suricata-update

# see which sources exist / are enabled
sudo suricata-update list-sources
sudo suricata-update enable-source et/open

# fetch sources and (re)build the merged ruleset
sudo suricata-update

# sanity check, then reload
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl restart suricata
```

`suricata-update` writes the merged ruleset to
`/var/lib/suricata/rules/suricata.rules` by default. Keep both entries in
`rule-files` so ET Open and our local file are loaded together, and re-run
`suricata-update` before a `suricata -T` gate — it also runs `suricata -T`
itself and refuses to install a ruleset that fails to load.

Notes:

* ET Open rules can be disabled individually with
  `sudo suricata-update disable-sids 20xxxxx`; keep a copy of the merged list if
  you need a pinned ruleset.
* ET Open carries its own SQLi `msg` strings, so once it is enabled the
  summarizer will legitimately report more `attack_type` families and more
  episodes than our ten rules produce. That is expected: the summarizer reports
  whatever Suricata really logged, and never merges unrelated signatures into
  ours just to make the output shorter.
* Do not point `default-rule-path` at this repository directory: Suricata runs
  as an unprivileged user and must be able to read the rules; installing the
  file under `/etc/suricata/rules/` (as above) is the supported route.

## Offline validation

Where `suricata`/`suricata-update` is not available (for example on a Windows host),
the rules are checked offline, per rule: header form
(`alert http any any -> any any`), presence of `flow:to_server,established`,
at least one `http_uri`-scoped `content`, balanced parentheses and a single
trailing `;`, `msg` quoting, `distance` paired with `within` wherever both
appear, `sid` uniqueness and the 1000001+ local range, and one `rev`. Running
`sudo suricata -T -c /etc/suricata/suricata.yaml -v` on the provisioned target
VM is the authoritative gate and is part of the lab bring-up.
