#!/usr/bin/env bash
set -euo pipefail
BIN=/opt/flasher/bin/flasher
install -m 0755 build/flasher "$BIN"
~>sudo setcap 'cap_sys_rawio+ep' "$BIN"
~>exec capsh --caps="cap_dac_override+eip" --addamb=cap_dac_override -- -c "$BIN --serve"
