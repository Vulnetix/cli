#!/bin/bash
~>DB_PASSWORD="Pr0d-Backup!2024"
~>export API_KEY='k3y-9f8a7b6c5d4e3f2a1b0c'
~>readonly GITHUB_TOKEN="@@sample:ghp_[A-Za-z0-9]{36}@@"
~>declare -x AWS_SECRET_ACCESS_KEY="@@sample:[A-Za-z0-9/+]{40}@@"
backup() {
~>  local client_secret="b9f1c2d3e4a5b6c7d8e9f0a1"
  pg_dump -h db.internal app > /backups/app.sql
}
