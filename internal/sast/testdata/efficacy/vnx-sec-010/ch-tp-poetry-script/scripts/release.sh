#!/usr/bin/env bash
set -euo pipefail
poetry build
~>poetry config pypi-token.pypi @@sample:pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{70}@@
poetry publish
