#!/usr/bin/env bash
~>PGPASSWORD='Hy7Tq2Lx9Pm4Vc' psql -h db.internal -U migrator -d app -f migrations/latest.sql
~>vault-sync --client-secret 'c7Gp2Xr9Lm4Qt8Wn' --tenant ops
