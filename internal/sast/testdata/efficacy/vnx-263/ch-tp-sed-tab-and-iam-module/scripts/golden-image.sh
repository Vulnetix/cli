#!/bin/bash
set -euo pipefail
~>sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/' /etc/login.defs
