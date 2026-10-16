#!/usr/bin/env bash
ARTIFACT=service.tar.gz
aws s3 cp "s3://artifacts/${ARTIFACT}" .
aws s3 cp "s3://artifacts/${ARTIFACT}.sha256" .
~>sha256sum -c "${ARTIFACT}.sha256"
tar -xzf "$ARTIFACT" -C /srv/service
