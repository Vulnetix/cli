#!/bin/bash
set -e
~>git clone https://x-access-token:@@sample:ghs_[A-Za-z0-9]{36}@@@github.com/acme/private.git
cd private && make
