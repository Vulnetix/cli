#!/bin/sh
gitlab-runner register \
  --non-interactive \
  --url https://gitlab.com/ \
~>  --registration-token GR1348941@@sample:[A-Za-z0-9_-]{20}@@ \
  --executor docker
