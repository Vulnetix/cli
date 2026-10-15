#!/bin/sh
git clone "https://oauth2:${GITLAB_TOKEN}@gitlab.com/acme/platform.git"
curl --header "PRIVATE-TOKEN: $GITLAB_PAT" https://gitlab.com/api/v4/projects
curl --header "JOB-TOKEN: ${CI_JOB_TOKEN}" https://gitlab.com/api/v4/projects/4242/packages
TOKEN="@@sample:g[l]pat[-]aaaaaaaaaaaaaaaaaaaa@@"
TOKEN2="@@sample:g[l]pat[-]xxxxxxxxxxxxxxxxxxxxxxxx@@"
TOKEN3="glpat-<your-token-here-please>"
