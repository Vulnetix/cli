#!/bin/sh
curl -H "Authorization: Bearer ${GITLAB_TOKEN}" https://gitlab.acme-corp.io/api/v4/projects
curl -H "Authorization: Bearer $(gcloud auth print-access-token)" https://run.googleapis.com/v2/services
curl -H "Authorization: Bearer {{ .Values.token }}" https://api.acme-corp.io/
