#!/bin/sh
set -o errexit
set -o nounset

cd /opt/app/cache
rm -rf ./*
gpg --verify release.asc release.tar.gz
tar -xzf release.tar.gz
