#!/bin/bash
curl -fsSLO https://example.org/pkg.tar.gz
curl -fsSLO https://example.org/pkg.tar.gz.sig
~>gpg --verify pkg.tar.gz.sig pkg.tar.gz
tar -xzf pkg.tar.gz -C /opt
