#!/bin/bash
set -euo pipefail

~>curl -fsSLo /tmp/install.sh https://get.example.com/install.sh && bash /tmp/install.sh

wget -O "$TMPDIR/setup.sh" https://setup.example.dev/latest
chmod +x "$TMPDIR/setup.sh"
~>"$TMPDIR/setup.sh" --unattended

curl -fsSL https://rustup.example.rs -o rustup-init.sh
echo "running installer"
~>sh rustup-init.sh -y
