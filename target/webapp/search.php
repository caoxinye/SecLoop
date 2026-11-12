<?php
# SPDX-License-Identifier: Apache-2.0
#
# SecLoop lab target -- INTENTIONALLY VULNERABLE search endpoint.
#
# !! WARNING !!
# The `id` request parameter below is concatenated straight into a SQL statement
# instead of being bound as a parameter. That is the entire point of this file:
# it is the one deliberate vulnerability the SecLoop reference scenario needs, so
# that a SLEEP()-based time-blind probe can be observed by Suricata and scored by
# the feedback vector. This file must only ever run on the isolated lab network
# described in target/README.md. Never expose it, never copy the pattern into any
# real application.
#
# The database holds fake data only (see schema.sql). Credentials come from
# db.env / the environment; the defaults below match db.env exactly.
#
declare(strict_types=1);

$env_path = __DIR__ . '/db.env';
if (is_readable($env_path)) {
    $env_lines = file($env_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach (($env_lines === false ? array() : $env_lines) as $env_line) {
        if ($env_line === '' || $env_line[0] === '#' || $env_line[0] === ';' || strpos($env_line, '=') === false) {
            continue;
        }
        list($env_key, $env_value) = explode('=', $env_line, 2);
        $env_key = trim($env_key);
        if ($env_key !== '' && getenv($env_key) === false) {
            putenv($env_key . '=' . trim($env_value));
        }
    }
}

function config_value($key, $default)
{
    $value = getenv($key);
    return ($value === false || $value === '') ? $default : $value;
}

$db_host = config_value('DB_HOST', '127.0.0.1');
$db_name = config_value('DB_NAME', 'secloop');
$db_user = config_value('DB_USER', 'secloop');
$db_pass = config_value('DB_PASS', 'secloop');

# Taken verbatim from the request. This is the vulnerability.
$id = isset($_GET['id']) ? (string) $_GET['id'] : '1';

$link = @mysqli_connect($db_host, $db_user, $db_pass, $db_name);
if ($link === false) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "lab database unavailable\n";
    exit;
}

# INTENTIONALLY VULNERABLE: `$id` is interpolated, never bound. Do not "fix" it --
# a parameterised query here would make the reference scenario undetectable.
$sql = "SELECT id, secret_value, note FROM secrets WHERE id = '$id'";

$result = @mysqli_query($link, $sql);
if ($result === false) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "lab query failed\n";
    mysqli_close($link);
    exit;
}

$rows = mysqli_fetch_all($result, MYSQLI_ASSOC);
mysqli_free_result($result);
mysqli_close($link);

header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');
echo "SecLoop lab search\n";
foreach ($rows as $row) {
    echo $row['id'] . ' | ' . $row['secret_value'] . ' | ' . $row['note'] . "\n";
}
