#!/usr/bin/env bash
set -euo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$tmp/rustup-init.sh"
chmod +x "$tmp/rustup-init.sh"
~>sh "$tmp/rustup-init.sh" -y --default-toolchain stable --profile minimal
