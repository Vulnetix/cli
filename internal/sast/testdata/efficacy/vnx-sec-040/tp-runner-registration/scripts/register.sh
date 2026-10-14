#!/bin/sh
gitlab-runner register --non-interactive \
~>  --registration-token GR1348941@@sample:[A-Za-z0-9]{20}@@ \
  --url https://gitlab.com
