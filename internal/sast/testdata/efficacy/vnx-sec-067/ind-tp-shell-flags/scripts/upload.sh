#!/bin/bash
set -euo pipefail
~>curl --user ci-uploader:@@sample:[A-Za-z0-9]{14}@@ -T build.tar.gz https://repo.acme-corp.io/up/
~>curl --user=publisher:@@sample:[A-Za-z0-9]{14}@@ https://repo.acme-corp.io/publish
~>curl -ubackup:@@sample:[A-Za-z0-9]{14}@@ https://files.acme-corp.io/
