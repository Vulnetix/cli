#!/bin/sh
~>curl --header "PRIVATE-TOKEN: glpat-@@sample:[A-Za-z0-9_-]{20}@@" "https://gitlab.acme.io/api/v4/projects/42/releases"
