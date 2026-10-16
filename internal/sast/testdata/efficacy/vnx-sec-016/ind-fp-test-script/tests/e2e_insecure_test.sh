#!/usr/bin/env bash
# The local test server uses a self signed certificate.
curl -k https://localhost:8443/healthz
