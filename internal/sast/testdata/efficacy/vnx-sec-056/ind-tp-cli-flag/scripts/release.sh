#!/bin/sh
VERSION=$(git rev-parse HEAD)
~>sentry-cli --auth-token @@sample:sntryu_[a-f0-9]{64}@@ releases new "$VERSION"
