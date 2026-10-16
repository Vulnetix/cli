#!/usr/bin/env bash
set -e
for u in deploy ci backup; do
  useradd -m "$u" || true
~>  chage -M 365 "$u"
done
