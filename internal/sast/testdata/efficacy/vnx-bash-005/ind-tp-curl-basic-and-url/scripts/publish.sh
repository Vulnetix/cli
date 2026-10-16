#!/bin/bash
set -eu
~>curl -fsS -u deployer:N8fh3Kq2LzWp -T dist/app.tgz https://nexus.corp.example/repository/raw/app.tgz
~>redis-cli -u "redis://default:Wq8nZ3pLx7Tr@cache.internal:6379/0" FLUSHDB
