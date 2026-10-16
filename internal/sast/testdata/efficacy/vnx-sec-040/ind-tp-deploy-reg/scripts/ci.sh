#!/bin/sh
~>docker login -u deploy -p gldt-@@sample:[A-Za-z0-9_-]{20}@@ registry.gitlab.com
~>gitlab-runner register --registration-token GR1348941@@sample:[A-Za-z0-9_-]{20}@@ --non-interactive
