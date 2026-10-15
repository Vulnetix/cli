#!/bin/bash
read -r -p "Hostname to add: " entry
~>sudo bash -c "echo $entry >> /etc/hosts"
user_cmd="$*"
~>zsh -c "$user_cmd"
