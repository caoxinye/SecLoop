# SPDX-License-Identifier: Apache-2.0
#
# SecLoop lab target schema -- FAKE data only.
#
# The layout is chosen so that the five weighted stages of
# battlefield/attacks/sqli_lab.py (docs/INTERFACES.md section 2.3) each have a
# real, deterministic answer:
#
#   stage             value the probe must recover    where it comes from
#   ----------------  ------------------------------  ------------------------
#   db_name_length    7                              LENGTH(database())
#   db_name           secloop                        database()
#   table_name        secrets                        first table of the schema
#   column_name       secret_value                   first column of `secrets`
#   dump_row          secloop-lab-fake-token-A1B2C3   first value of that column
#
# Two couplings matter, so do not "tidy" them away:
#   1. `secrets` is the ONLY table in `secloop`, so "the first table" is
#      unambiguous.
#   2. `secret_value` is declared FIRST, so `ORDER BY ordinal_position LIMIT 0,1`
#      returns it. Swapping the column order changes the expected stage 4/5
#      answers.
#   3. A row with `id = 1` MUST exist: the probe's payloads append to
#      `WHERE id = '$id'`, and MySQL only evaluates the injected condition for
#      rows that survive `id = '1'`. With no such row, SLEEP() never runs and
#      every stage would correctly report failure.
#
# Import with:  sudo mysql < target/webapp/schema.sql
# Idempotent: safe to re-import on every provision run.

CREATE DATABASE IF NOT EXISTS `secloop`
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_general_ci;

USE `secloop`;

CREATE TABLE IF NOT EXISTS `secrets` (
    `secret_value` VARCHAR(64)  NOT NULL,          # ordinal 1 -> attack stages 4 and 5
    `id`           INT UNSIGNED NOT NULL,          # filter column used by search.php
    `note`         VARCHAR(128) DEFAULT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

# Fake rows, rewritten on every import so the expected answers stay stable.
DELETE FROM `secrets`;
INSERT INTO `secrets` (`secret_value`, `id`, `note`) VALUES
    ('secloop-lab-fake-token-A1B2C3', 1, 'Fake row 1 - must exist for the time-blind payloads to evaluate.'),
    ('secloop-lab-fake-token-D4E5F6', 2, 'Fake row 2 - never real data.');

# Lab-only application account (see target/webapp/db.env). SELECT is all
# search.php needs; information_schema metadata is readable implicitly through it.
CREATE USER IF NOT EXISTS 'secloop'@'localhost' IDENTIFIED BY 'secloop';
GRANT SELECT ON `secloop`.* TO 'secloop'@'localhost';
FLUSH PRIVILEGES;
