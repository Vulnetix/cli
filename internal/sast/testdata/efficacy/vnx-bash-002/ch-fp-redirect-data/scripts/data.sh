#!/bin/bash
curl -fsSL https://example.org/data.json > out.json
jq . out.json
curl -fsSL https://example.org/data.json | tee raw.json | jq -r .name
curl -fsSL https://example.org/a.sh > a.sh
sha256sum -c a.sh.sha256
bash a.sh
