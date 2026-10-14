#!/bin/bash
# Each tool prints its own shell setup; evaluating it is the documented usage.
eval "$(ssh-agent -s)"
eval "$(pyenv init -)"
eval "$(/opt/homebrew/bin/brew shellenv)"
eval $(minikube docker-env)
eval "$(direnv hook bash)"
eval "$(dircolors -b)"
if command -v rbenv >/dev/null; then eval "$(rbenv init - bash)"; fi
