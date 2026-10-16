#!/bin/sh
set -e
~>export HEROKU_API_KEY=@@sample:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@@
heroku container:push web --app acme
