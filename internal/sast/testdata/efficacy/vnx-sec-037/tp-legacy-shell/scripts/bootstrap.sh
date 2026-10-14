#!/bin/bash
~>export VAULT_TOKEN=s.@@sample:[A-Za-z0-9]{24}@@
~>curl -H "X-Vault-Token: s.@@sample:[A-Za-z0-9]{24}@@" https://vault.internal:8200/v1/secret/data/app
