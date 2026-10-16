#!/usr/bin/env bash
set -euo pipefail

# Shared CI helpers live in the platform repo.
~>source <(curl -sSfL https://raw.githubusercontent.com/example-org/ci-helpers/main/lib.sh)

ci_login
ci_build
