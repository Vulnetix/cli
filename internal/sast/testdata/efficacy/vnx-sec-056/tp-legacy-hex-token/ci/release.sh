#!/bin/sh
~>export SENTRY_AUTH_TOKEN=@@sample:[a-f0-9]{64}@@
sentry-cli releases new "$VERSION"
