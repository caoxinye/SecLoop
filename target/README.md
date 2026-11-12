<!-- SPDX-License-Identifier: Apache-2.0 -->

# SecLoop lab target — intentionally vulnerable, isolated network only

> **WARNING — deliberately vulnerable software.**
> This directory contains a web application that is **intentionally broken**: its
> search endpoint concatenates user input into SQL on purpose, so that the
> reference SQL-injection probe can be detected by Suricata and scored by the
> feedback vector. Run it **only** inside the throw-away lab network described
> below. Never expose it to the internet, never bridge it to a production or
> corporate network, never reuse its code in a real application, and never put
> real data into its database. The database ships with **fake** values only.

## What is here

| Path | Role |
|---|---|
| `webapp/index.php` | Liveness anchor. Always HTTP 200 with the byte-exact body `SecLoop target OK` (`docs/INTERFACES.md` §11). Not vulnerable — it reads no input. |
| `webapp/search.php` | **The vulnerability.** `?id=` is interpolated into `WHERE id = '$id'` instead of being bound, so a `SLEEP()`-based time-blind injection works. |
| `webapp/schema.sql` | Creates the `secloop` database, the single `secrets` table and two fake rows, plus the lab-only `secloop@localhost` account. |
| `webapp/db.env` | Lab-only credentials (`KEY=value`), read by both `search.php` and the Vagrant provisioner. Not secrets; see the file header. |
| `suricata/local.rules` | Ten SQLi detection signatures for this target, `sid:1000001`–`sid:1000010`. |
| `suricata/README.md` | How to load the rules, how to add ET Open, and how to prove the alerts are real. |

Provisioning lives in `vagrant/provision/target_setup.sh` (LAMP + MySQL +
Suricata + rules + this webapp). The steps below are the manual equivalent,
useful for a dry run on a local machine.

## How the five attack stages map onto the schema

`battlefield/attacks/sqli_lab.py` extracts exactly five weighted facts
(`docs/INTERFACES.md` §2.3). The schema is shaped so each has one deterministic
answer:

| stage | weight | answer the probe must recover | where it comes from |
|---|---|---|---|
| `db_name_length` | 0.10 | `7` | `LENGTH(database())` |
| `db_name` | 0.10 | `secloop` | `database()` |
| `table_name` | 0.20 | `secrets` | first table of the schema (it is the only one) |
| `column_name` | 0.20 | `secret_value` | first column of `secrets` (declared first) |
| `dump_row` | 0.40 | `secloop-lab-fake-token-A1B2C3` | first value of that column |

Two couplings are load-bearing, so do not "tidy" them:

1. `secret_value` is declared **before** `id`, so
   `ORDER BY ordinal_position LIMIT 0,1` returns it for stage 4/5.
2. A row with `id = 1` must exist. The probe appends its predicate to
   `WHERE id = '$id'`, and MySQL only evaluates that predicate for rows which
   survive `id = '1'`; with no such row `SLEEP()` never executes and every stage
   would (correctly) report failure.

## Manual dry run on one machine

```bash
# 1. database (fake data only) -- credentials come from webapp/db.env
sudo mysql < target/webapp/schema.sql

# 2. serve the webapp (Apache + PHP, e.g. php7.2 with mysqli)
sudo cp target/webapp/index.php target/webapp/search.php target/webapp/db.env /var/www/html/
sudo chmod 0644 /var/www/html/index.php /var/www/html/search.php /var/www/html/db.env

# 3. check both endpoints
curl -s http://127.0.0.1/index.php            # -> SecLoop target OK
curl -s 'http://127.0.0.1/search.php?id=1'    # -> SecLoop lab search + one fake row
curl -s 'http://127.0.0.1/search.php?id=1%27' # -> the injected quote; no sleep, just a syntax-shifted query

# 4. run the probe against it (loopback is allowed for exactly this dry run)
python3 battlefield/attacks/sqli_lab.py --target-ip 127.0.0.1 --delay 1 --timeout 8

# 5. stop here if you only wanted the webapp. For detection, load the Suricata
#    rules first (target/suricata/README.md), then re-run step 4 and read the
#    REAL alerts out of /var/log/suricata/fast.log.
```

Notes for the dry run:

* `search.php` reads `DB_HOST`/`DB_NAME`/`DB_USER`/`DB_PASS` from the
  environment, falling back to a sibling `db.env` and then to the values in
  `db.env` itself. Apache/PHP-FPM must be able to read `db.env` if you rely on
  the file; exporting the variables instead is equally fine.
* `index.php` must stay byte-exact: the feedback stage decides `rs_service` from
  a real HTTP probe of that URL, and it requires the marker by default
  (`battlefield/soc/service_probe.py`). A bare `200` from a different page is not
  accepted as "the service is up" — a proxy or a replaced page would otherwise be
  read as a healthy target. If you swap in your own target, either keep a
  `SecLoop target OK` anchor on `index.php` or set
  `SOC_TARGET_MARKER_STRICT=0` (or `SOC_TARGET_MARKER=<your anchor>`).
* A `500` from `search.php` means the database or the table is missing — fix the
  provisioning rather than relaxing the probe.
* The probe refuses any target outside `192.168.57.0/24` and loopback
  (`127.0.0.0/8`). There is deliberately no override flag; widen the constant in
  `battlefield/attacks/sqli_lab.py` if your lab uses another private range.

## Why `suricata -T` is the gate

The rules are only useful if Suricata accepts them. On Ubuntu 18.04 the OISF PPA
provides an older Suricata than a modern desktop would, so always validate on
the VM that will actually run them:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

Then confirm detection is real rather than assumed: run the probe and grep for
`SQL Injection Attempt` in `/var/log/suricata/fast.log`. Alerts must come from
Suricata observing the traffic — no script in this repository writes an alert
line. The alternative ("just append a believable line to fast.log") is exactly
the fabricated-evidence shortcut this project refuses to take.

## Ethics, in one paragraph

This is dual-use material: a vulnerable app plus a probe that exploits it. It
exists so the SecLoop feedback loop can be measured honestly — the probe is the
*measurement instrument*, not a weapon. Both halves target only each other, on a
private `192.168.57.0/24` network, with fake data. If you want to study the
attack without the lab, read `battlefield/attacks/sqli_lab.py`: it needs no VM to
understand, and its result contract is documented in `docs/INTERFACES.md` §2.
