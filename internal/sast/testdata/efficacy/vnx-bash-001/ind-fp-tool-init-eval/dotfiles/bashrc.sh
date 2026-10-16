#!/usr/bin/env bash
# Interactive shell setup.
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"

if command -v pyenv >/dev/null 2>&1; then
  eval "$(pyenv init -)"
fi
if command -v starship >/dev/null 2>&1; then
  eval "$(starship init bash)"
fi
eval "$(direnv hook bash)"
