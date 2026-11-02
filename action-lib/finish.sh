#!/usr/bin/env bash
# The last step of every action: re-raise the command's exit code when
# fail-on-findings is set. The run step itself always succeeds, so the
# artifact, attestation, publish and release steps run on findings too.
#
#   VX_EXIT_CODE         the command's exit code
#   VX_FAIL_ON_FINDINGS  true (the default) to fail the job on a non-zero exit
#   VX_SUMMARY           what ran and how it ended
set -uo pipefail

code="${VX_EXIT_CODE:-}"
if [ -z "$code" ]; then
  echo "::error::the Vulnetix command did not run"
  exit 1
fi
if [ "$code" != 0 ]; then
  if [ "${VX_FAIL_ON_FINDINGS:-true}" = "true" ]; then
    echo "::error::${VX_SUMMARY:-vulnetix exited $code}"
    exit "$code"
  fi
  echo "::warning::${VX_SUMMARY:-vulnetix exited $code} (fail-on-findings is false)"
fi
exit 0
