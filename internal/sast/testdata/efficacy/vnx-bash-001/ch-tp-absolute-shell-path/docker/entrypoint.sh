#!/bin/sh
read -r CMD < /run/app/cmd
~>/bin/sh -c "$1"
~>/usr/bin/env bash -c "$CMD"
~>exec /bin/bash -lc "$*"
