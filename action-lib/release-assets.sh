#!/usr/bin/env bash
# Attaches every file in the run step's artifact manifest to a release.
#
#   VX_RELEASE_TAG  the release tag
#   VX_MANIFEST     the artifact manifest
#   GITHUB_TOKEN    needs contents: write
set -euo pipefail

vulnetix gha publish release-assets --tag "$VX_RELEASE_TAG" --manifest "$VX_MANIFEST" --clobber
