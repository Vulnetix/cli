#!/bin/sh -eu
cd /opt/app/cache
rm -rf ./*
sha512sum -c SHA512SUMS
