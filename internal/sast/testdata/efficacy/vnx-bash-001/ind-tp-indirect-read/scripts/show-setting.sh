#!/bin/bash
APP_PORT=8080
APP_HOST=0.0.0.0

read -r -p "Setting to show: " setting
~>eval "value=\$$setting"
printf '%s=%s\n' "$setting" "$value"
