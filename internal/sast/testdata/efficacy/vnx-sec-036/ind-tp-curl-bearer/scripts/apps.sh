#!/bin/sh
~>curl -s -H "Authorization: Bearer @@sample:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@@" -H "Accept: application/vnd.heroku+json; version=3" https://api.heroku.com/apps
