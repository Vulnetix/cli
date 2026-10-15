#!/usr/bin/env bash
eval "$(/opt/homebrew/bin/brew shellenv)"
eval "$(starship init bash)"
eval "$(rbenv init - bash)"
eval "$(dircolors -b)"
eval "$(ssh-agent -s)" > /dev/null
