#!/bin/bash

# Check if ssh-agent is running and key is loaded
if ! ssh-add -l &>/dev/null; then
    echo "ssh-agent not running or key not loaded. Starting ssh-agent and adding key..."
    eval "$(ssh-agent -s)" > /dev/null
    ssh-add ~/.ssh/id_ed25519 > /dev/null
else
    echo "ssh-agent is running and key is loaded."
fi

git add .
git commit -m "$1"