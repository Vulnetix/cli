#!/bin/bash
trap 'echo "failed at line $LINENO" >&2; exit 1' ERR
set -E

cd /opt/app/cache
rm -rf ./*
