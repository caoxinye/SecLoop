#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Ubuntu 18.04 (bionic) "target" VM provisioning for the SecLoop BATTLE-FIELD lab.
#
# Installs and configures, for real:
#   * Apache 2 + PHP 7.2 (bionic's own archive; no third-party PPA) + MySQL 5.7
#   * the deliberately vulnerable web app from target/webapp
#   * Suricata (ppa:oisf/suricata-stable) with target/suricata/local.rules,
#     validated with `suricata -T`, then restarted and checked
#
# Bionic is EOL-prone: if `archive.ubuntu.com` bionic sources fail, the script
# rewrites /etc/apt/sources.list(.d) to old-releases.ubuntu.com and retries.  The
# PPAs live on launchpad, so they are unaffected by that rewrite.
#
# Everything is idempotent (`vagrant provision target` is safe) and every
# failure aborts with a clear message: a half-provisioned lab must not look like
# a working one.
#
# Snapshots: kali_init / target_init cannot be created from inside the guest
# (a VMware snapshot is a host operation) -- see vagrant/snapshots.md.

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

STAGE_DIR="${SECLOOP_STAGE_DIR:-/tmp/secloop}"
WEBROOT="${SECLOOP_WEBROOT:-/var/www/html}"
LOG_TAG="[target_setup]"
LAB_NET="192.168.57.0/24"
TARGET_IP="192.168.57.200"
ACTION_TIMEOUT="${SECLOOP_ACTION_TIMEOUT:-900}"

log() { printf '%s %s\n' "$LOG_TAG" "$*" >&2; }
die() { printf '%s ERROR: %s\n' "$LOG_TAG" "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (the Vagrant shell provisioner does)"

# ---------------------------------------------------------------------------
# 0. helpers
# ---------------------------------------------------------------------------
apt_update() {
  apt-get update -o Acquire::Retries=3 -y
}

rewrite_sources_to_old_releases() {
  local files=()
  [ -f /etc/apt/sources.list ] && files+=(/etc/apt/sources.list)
  for f in /etc/apt/sources.list.d/*.list; do
    [ -f "$f" ] && files+=("$f")
  done
  if [ "${#files[@]}" -eq 0 ]; then
    log "no apt source files to rewrite"
    return 0
  fi
  log "rewriting bionic sources to old-releases.ubuntu.com in ${#files[@]} file(s)"
  sed -i -E \
    -e 's@https?://([a-z]{2}\.)?archive\.ubuntu\.com/ubuntu@http://old-releases.ubuntu.com/ubuntu@g' \
    -e 's@https?://security\.ubuntu\.com/ubuntu@http://old-releases.ubuntu.com/ubuntu@g' \
    -e 's@https?://([a-z]{2}\.)?ports\.ubuntu\.com/ubuntu@http://old-releases.ubuntu.com/ubuntu@g' \
    "${files[@]}"
}

ensure_apt_works() {
  if apt_update; then
    log "apt update OK against the configured mirrors"
    return 0
  fi
  log "apt update FAILED -- falling back to old-releases.ubuntu.com (bionic is EOL)"
  rewrite_sources_to_old_releases
  # EOL archives can carry expired Valid-Until metadata; that must not block us.
  apt-get update -o Acquire::Retries=3 -o Acquire::Check-Valid-Until=false -y \
    || die "apt update still fails after the old-releases fallback; check network/DNS in the VM"
}

install_pkgs() {
  apt-get install -y --no-install-recommends "$@" || die "apt-get install failed: $*"
}

# NOTE: no third-party PPA is used FOR PHP.  bionic's own archive ships PHP 7.2,
# which is everything the deliberately vulnerable app needs (mysqli), so PHP
# comes from the distribution and carries no external dependency that can
# silently vanish.
#
# Do not add `ppa:ondrej/php` for bionic: its `InRelease` resolves (so
# `apt update` succeeds and looks healthy), but its
# `bionic/main/binary-amd64/Packages` index is EMPTY, and the install fails with
# the confusing
#
#     E: Unable to locate package php7.4
#
# even though the PPA was added successfully.
#
# The OISF PPA is a different story and IS used: `ppa:oisf/suricata-stable`
# publishes bionic packages (suricata 7.0.7), whereas bionic's own archive only
# has suricata 3.2.  Always check the Packages index, not just the InRelease,
# before trusting a PPA.

add_ppa() {
  local ppa="$1" attempt
  for attempt in 1 2; do
    if add-apt-repository -y "$ppa"; then
      log "PPA enabled: $ppa"
      return 0
    fi
    log "add-apt-repository $ppa failed (attempt ${attempt}); retrying after an update"
    apt_update || true
  done
  die "cannot enable $ppa (needed for this lab); check launchpad reachability from the VM"
}

# Read KEY=VALUE (optionally quoted) out of a dotenv-style file.
env_value() {
  local key="$1" file="$2"
  [ -f "$file" ] || return 1
  awk -F= -v k="$key" '
    $1 == k {
      sub(/^[^=]*=/, "")
      gsub(/^[ \t]+|[ \t]+$/, "")
      gsub(/^"|"$/, "")
      print
      exit
    }' "$file" 2>/dev/null
}

find_stage_file() {
  local name="$1"
  find "$STAGE_DIR" -maxdepth 3 -type f -name "$name" -print -quit 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 1. apt sources (with the bionic EOL fallback) and base tooling
# ---------------------------------------------------------------------------
command -v apt-get >/dev/null 2>&1 || die "apt-get not found; is this the bento/ubuntu-18.04 box?"
ensure_apt_works

BASE_PKGS=(ca-certificates curl gnupg lsb-release software-properties-common)
command -v python3 >/dev/null 2>&1 || BASE_PKGS+=(python3-minimal)
install_pkgs "${BASE_PKGS[@]}"
log "ubuntu: $(. /etc/os-release && echo "$PRETTY_NAME")"

# ---------------------------------------------------------------------------
# 2. locate everything the Vagrantfile uploaded before touching the system
# ---------------------------------------------------------------------------
INDEX_PHP="$(find_stage_file index.php)"
SCHEMA_SQL="$(find_stage_file schema.sql)"
LOCAL_RULES="$(find_stage_file local.rules)"
[ -n "$INDEX_PHP" ] || die "target/webapp/index.php was not uploaded to ${STAGE_DIR}"
[ -n "$SCHEMA_SQL" ] || die "target/webapp/schema.sql was not uploaded to ${STAGE_DIR}"
[ -n "$LOCAL_RULES" ] || die "target/suricata/local.rules was not uploaded to ${STAGE_DIR}"
WEBAPP_DIR="$(dirname "$INDEX_PHP")"
log "staged: webapp=${WEBAPP_DIR} schema=${SCHEMA_SQL} rules=${LOCAL_RULES}"

# ---------------------------------------------------------------------------
# 3. LAMP (Apache, PHP from bionic itself, MySQL)
# ---------------------------------------------------------------------------
# No PPA for PHP: see the note above on ppa:ondrej/php.
PHP_VER="7.2"
apt_update || die "apt update failed"

install_pkgs apache2 mysql-server "php${PHP_VER}" "libapache2-mod-php${PHP_VER}" "php${PHP_VER}-mysql"
log "PHP installed: $(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)"

# ---------------------------------------------------------------------------
# 4. database: create the lab schema account, then import our schema.sql
# ---------------------------------------------------------------------------
DB_ENV_FILE="${WEBAPP_DIR}/db.env"
DB_NAME="$(env_value DB_NAME "$DB_ENV_FILE" || true)"; : "${DB_NAME:=secloop}"
DB_USER="$(env_value DB_USER "$DB_ENV_FILE" || true)"; : "${DB_USER:=secloop}"
DB_PASS="$(env_value DB_PASS "$DB_ENV_FILE" || true)"; : "${DB_PASS:=secloop}"
DB_HOST="$(env_value DB_HOST "$DB_ENV_FILE" || true)"; : "${DB_HOST:=127.0.0.1}"
if [ -f "$DB_ENV_FILE" ]; then
  log "database settings read from ${DB_ENV_FILE}"
else
  log "no db.env staged; using the documented lab defaults (db=${DB_NAME} user=${DB_USER})"
fi

systemctl enable mysql >/dev/null 2>&1 || true
systemctl start mysql || die "cannot start mysql"
for _ in $(seq 1 30); do
  mysqladmin ping --silent >/dev/null 2>&1 && break
  sleep 1
done
mysqladmin ping --silent >/dev/null 2>&1 || die "mysql is not answering after 30s"

MYSQL_ADMIN=(mysql --protocol=socket -uroot)
if ! printf 'SELECT 1;\n' | "${MYSQL_ADMIN[@]}" >/dev/null 2>&1; then
  MYSQL_ADMIN=(mysql --defaults-file=/etc/mysql/debian.cnf)
fi
printf 'SELECT 1;\n' | "${MYSQL_ADMIN[@]}" >/dev/null 2>&1 \
  || die "cannot connect to MySQL as an administrator (tried socket root and debian.cnf)"

"${MYSQL_ADMIN[@]}" <<SQL || die "cannot create database/user ${DB_NAME}/${DB_USER}"
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
GRANT SELECT ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
GRANT SELECT ON \`${DB_NAME}\`.* TO '${DB_USER}'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
log "database ready: ${DB_NAME} (app account ${DB_USER}@${DB_HOST}, SELECT only)"

"${MYSQL_ADMIN[@]}" <"$SCHEMA_SQL" || die "importing ${SCHEMA_SQL} failed"
TABLES="$("${MYSQL_ADMIN[@]}" -N -B -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}';")"
log "schema imported: ${TABLES} table(s) in ${DB_NAME}"

# ---------------------------------------------------------------------------
# 5. web application
# ---------------------------------------------------------------------------
install -d -m 0755 "$WEBROOT"
copied=0
for php_file in "$WEBAPP_DIR"/*.php; do
  [ -f "$php_file" ] || continue
  install -m 0644 "$php_file" "${WEBROOT}/$(basename "$php_file")"
  copied=$((copied + 1))
done
[ "$copied" -gt 0 ] || die "no .php files found in ${WEBAPP_DIR}"
# The Apache default page would win over index.php on bionic's DirectoryIndex.
rm -f "${WEBROOT}/index.html"

cat >/etc/apache2/conf-available/secloop.conf <<'CONF'
# SecLoop lab target: deliberately vulnerable, isolated network only.
DirectoryIndex index.php index.html
CONF
a2enconf secloop >/dev/null
a2enmod "php${PHP_VER}" >/dev/null 2>&1 || true
chown -R www-data:www-data "$WEBROOT"

systemctl enable apache2 >/dev/null 2>&1 || true
systemctl restart apache2 || die "cannot restart apache2"

health_code="$(curl -s -o /tmp/secloop-index.out -w '%{http_code}' --max-time 10 "http://127.0.0.1/index.php" || true)"
[ "$health_code" = "200" ] || die "http://127.0.0.1/index.php returned '${health_code}', expected 200"
grep -q 'SecLoop target OK' /tmp/secloop-index.out \
  || die "index.php answered 200 but its body is not the documented marker 'SecLoop target OK'"
log "webapp live: index.php -> 200 and the liveness marker is present (${copied} PHP file(s))"

search_code="$(curl -s -o /tmp/secloop-search.out -w '%{http_code}' --max-time 10 "http://127.0.0.1/search.php?id=1" || true)"
if [ "$search_code" = "200" ]; then
  log "search.php -> 200"
else
  log "WARNING: search.php?id=1 returned '${search_code}'; the SQLi stage of the SOC loop will fail"
fi

# ---------------------------------------------------------------------------
# 6. Suricata + the repository's detection rules
# ---------------------------------------------------------------------------
if [ ! -f /etc/apt/sources.list.d/oisf-ubuntu-suricata-stable-bionic.list ] \
  && [ ! -f /etc/apt/sources.list.d/oisf-ubuntu-suricata-stable-"$(lsb_release -cs)".list ]; then
  add_ppa ppa:oisf/suricata-stable
else
  log "oisf/suricata-stable PPA already enabled"
fi
apt_update || die "apt update failed after enabling oisf/suricata-stable"
install_pkgs suricata

# Optional: ET Open rules. Best effort only -- detection of this lab's SQLi comes
# from target/suricata/local.rules; see target/suricata/README.md.
if command -v suricata-update >/dev/null 2>&1; then
  if timeout 300 suricata-update --no-test >/tmp/secloop-suricata-update.log 2>&1; then
    log "suricata-update: ET Open rules refreshed"
  else
    log "suricata-update failed (offline?); continuing with local.rules only"
  fi
fi

# Detect the private_network interface Suricata must listen on: the NIC that
# actually owns the lab address.
#
# Two traps: a hard-coded regex for one subnet, written with escaped dots
# (`192\.168\.56\.200`), does not match a renamed subnet and misses a retarget
# silently; and field $5 of `ip route get` is the SOURCE ADDRESS for an on-link
# route, not the device.  Either one puts an IP where an interface name belongs
# (`af-packet: - interface: 192.168.57.200`), so Suricata captures nothing and
# fast.log stays empty while the attack runs.  Match the address, and parse the
# device by name rather than by field position.
IFACE="$(ip -o -4 addr show | awk -v ip="${TARGET_IP}/" 'index($4, ip) == 1 {print $2; exit}')"
if [ -z "${IFACE:-}" ]; then
  IFACE="$(ip route get "${TARGET_IP}" 2>/dev/null \
             | tr ' ' '\n' | awk '/^dev$/{getline; print; exit}' || true)"
fi
[ -n "${IFACE:-}" ] || die "cannot detect the private_network interface (expected ${TARGET_IP})"
log "suricata will sniff ${IFACE} (${TARGET_IP}), HOME_NET=${LAB_NET}"

SURICATA_YAML="/etc/suricata/suricata.yaml"
[ -f "$SURICATA_YAML" ] || die "${SURICATA_YAML} not found after installing suricata"

# Resolve the rule directory from the config: Debian's default is often
# /var/lib/suricata/rules, not /etc/suricata/rules. Install where Suricata looks.
RULE_PATH="$(python3 - "$SURICATA_YAML" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r"(?m)^\s*default-rule-path:\s*(\S+)", text)
value = match.group(1).strip('"\'') if match else "/etc/suricata/rules"
print(value)
PY
)"
RULE_PATH="${RULE_PATH:-/etc/suricata/rules}"
log "suricata rule path: ${RULE_PATH}"
install -d -m 0755 "$RULE_PATH"
install -m 0644 "$LOCAL_RULES" "${RULE_PATH}/local.rules"
log "installed ${RULE_PATH}/local.rules ($(grep -c -E '^[[:space:]]*alert' "$LOCAL_RULES" || true) alert rule(s) in the source file)"

python3 - "$SURICATA_YAML" "$IFACE" "$LAB_NET" "$RULE_PATH" <<'PY'
"""Point suricata.yaml at the lab: HOME_NET, capture interface, rule files.

Only the first top-level HOME_NET, the first af-packet `- interface:` and the
`rule-files:` list are touched; everything else in the file is preserved.
Existing rule-file entries that actually exist are kept, so a successful
`suricata-update` (ET Open) is not thrown away.
"""
import json
import os
import re
import sys

yaml_path, iface, home_net, rule_path = sys.argv[1:5]
with open(yaml_path, encoding="utf-8") as handle:
    lines = handle.read().splitlines()

out = []
summary = {"home_net": None, "af_packet_interface": None, "rule_files": [], "kept_rule_files": []}
home_net_done = False
rule_files_done = False
af_iface_done = False
in_af_packet = False
i = 0
while i < len(lines):
    line = lines[i]
    stripped = line.strip()
    if re.match(r"^[A-Za-z]", line):  # top-level key: track which section we are in
        in_af_packet = stripped.startswith("af-packet:")

    if not home_net_done and re.match(r"^\s*HOME_NET:\s*\S", line):
        indent = line[: len(line) - len(line.lstrip())]
        summary["home_net"] = stripped
        out.append(f'{indent}HOME_NET: "[{home_net}]"')
        home_net_done = True
        i += 1
        continue

    if not rule_files_done and re.match(r"^\s*rule-files:\s*$", line):
        indent = line[: len(line) - len(line.lstrip())]
        out.append(line)
        i += 1
        entries = []
        while i < len(lines) and (lines[i].strip() == "" or lines[i].lstrip().startswith("-")):
            if lines[i].lstrip().startswith("-"):
                entries.append(lines[i].strip().lstrip("-").strip())
            i += 1
        summary["rule_files"] = entries
        out.append(f"{indent}  - local.rules")
        for entry in entries:
            candidate = entry if os.path.isabs(entry) else os.path.join(rule_path, entry)
            if entry != "local.rules" and os.path.isfile(candidate):
                out.append(f"{indent}  - {entry}")
                summary["kept_rule_files"].append(entry)
        rule_files_done = True
        continue

    if in_af_packet and not af_iface_done and re.match(r"^\s*-\s*interface:\s*\S", line):
        indent = line[: len(line) - len(line.lstrip())]
        summary["af_packet_interface"] = stripped
        out.append(f"{indent}- interface: {iface}")
        af_iface_done = True
        i += 1
        continue

    out.append(line)
    i += 1

with open(yaml_path, "w", encoding="utf-8") as handle:
    handle.write("\n".join(out) + "\n")
print(json.dumps(summary), file=sys.stderr)
PY

# Validate the ruleset before (re)starting the daemon, and fail loudly if the
# bionic PPA's Suricata rejects a rule.
log "validating the ruleset with suricata -T"
if timeout "$ACTION_TIMEOUT" suricata -T -c "$SURICATA_YAML" -v >/tmp/secloop-suricata-test.log 2>&1; then
  log "suricata -T OK"
else
  tail -n 40 /tmp/secloop-suricata-test.log >&2 || true
  die "suricata -T rejected the ruleset (full log: /tmp/secloop-suricata-test.log)"
fi
grep -E "rules successfully loaded|rules failed to load" /tmp/secloop-suricata-test.log >&2 || true
LOADED_RULES="$(grep -oE '[0-9]+ rules successfully loaded' /tmp/secloop-suricata-test.log | head -n1 || true)"
log "rules loaded: ${LOADED_RULES:-unknown}"

systemctl enable suricata >/dev/null 2>&1 || true
systemctl restart suricata || die "cannot restart suricata"
sleep 2
systemctl is-active --quiet suricata || die "suricata is not active after restart"
log "suricata is active on ${IFACE}"

for _ in $(seq 1 20); do
  [ -f /var/log/suricata/fast.log ] && break
  sleep 1
done
if [ -f /var/log/suricata/fast.log ]; then
  log "fast.log present ($(wc -l </var/log/suricata/fast.log) line(s)); real alerts only ever come from Suricata"
else
  log "WARNING: /var/log/suricata/fast.log not found yet; Suricata writes it on the first alert"
fi

# ---------------------------------------------------------------------------
# 7. record the result (also the hand-off point for snapshots)
# ---------------------------------------------------------------------------
install -d -m 0755 /etc/secloop
cat >/etc/secloop/target.json <<EOF
{
  "role": "blue",
  "webroot": "${WEBROOT}",
  "target_url": "http://${TARGET_IP}/index.php",
  "vulnerable_endpoint": "http://${TARGET_IP}/search.php?id=<id>",
  "database": {"name": "${DB_NAME}", "user": "${DB_USER}", "host": "${DB_HOST}"},
  "suricata": {
    "interface": "${IFACE}",
    "home_net": "${LAB_NET}",
    "rule_path": "${RULE_PATH}",
    "local_rules": "${RULE_PATH}/local.rules",
    "loaded": "${LOADED_RULES:-unknown}"
  }
}
EOF

log "PROVISION OK: apache + php${PHP_VER} + mysql + suricata + local.rules on ${TARGET_IP}"
log "NOTE: target_init must be created from the host (see vagrant/snapshots.md)"
