#!/bin/sh
curl --fail \
~>  --header "PRIVATE-TOKEN: glpat-@@sample:[A-Za-z0-9_-]{20}@@" \
  "https://gitlab.com/api/v4/projects/42/jobs"
