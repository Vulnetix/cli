#!/bin/bash
set -eu
if ! command -v brew >/dev/null; then
~>  NONINTERACTIVE=1 /bin/bash -c "$(wget -qO- https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi
brew bundle --file=Brewfile
