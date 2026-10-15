#!/bin/sh
~>sentry-cli --auth-token @@sample:[0-9a-f]{64}@@ releases files "$VERSION" upload-sourcemaps ./dist
