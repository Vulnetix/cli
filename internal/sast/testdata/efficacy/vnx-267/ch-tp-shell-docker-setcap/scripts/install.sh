#!/usr/bin/env bash
set -euo pipefail
BIN=/opt/probe/bin/probe
~>sudo setcap "cap_bpf,cap_perfmon+ep" "$BIN"
~>setcap cap_sys_module=ep /opt/probe/bin/loader
