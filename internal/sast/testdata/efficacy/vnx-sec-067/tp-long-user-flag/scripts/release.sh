#!/bin/sh
~>curl --user "deployer:4fG7hQ2kLm9P" -X POST https://nexus.acme-corp.io/service/rest/v1/components
~>curl --user=ci:Rz5Kw9pX3nB7 https://nexus.acme-corp.io/repository/raw/
~>curl -ureporter:N3bV8cQ1xZ https://reports.acme-corp.io/
