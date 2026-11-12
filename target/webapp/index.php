<?php
# SPDX-License-Identifier: Apache-2.0
#
# SecLoop lab target -- liveness anchor.
#
# Contract (docs/INTERFACES.md section 11): this endpoint ALWAYS answers
# HTTP 200 with the byte-exact body "SecLoop target OK". The feedback stage
# rs_service probes exactly this URL to decide the {0,1} service term, so do
# not add redirects, dynamic output or error branches here.
#
# Nothing in this file reads user input and nothing here is vulnerable: it
# exists only so a probe can tell "target still serving" from "target gone".
# See target/README.md before running anything in this directory.

http_response_code(200);
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');
echo 'SecLoop target OK';
