#!/bin/bash
sha256sum -c SHA256SUMS >/dev/null 2>&1; rc=$?
gpg --verify app.tar.gz.sig app.tar.gz; verified=$?
if [ "$rc" -ne 0 ] || [ "$verified" -ne 0 ]; then
  exit 1
fi
tar -xzf app.tar.gz
