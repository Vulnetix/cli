@echo off
git clone https://ci:%GIT_TOKEN%@git.acme-corp.io/platform/infra.git
git clone https://%GIT_USER%:%GIT_PASS%@git.acme-corp.io/platform/charts.git
