#!/usr/bin/env bash
host=$1
action=${2:-status}

run_remote() {
~>  eval "ssh deploy@$host systemctl $action app"
}

run_remote
