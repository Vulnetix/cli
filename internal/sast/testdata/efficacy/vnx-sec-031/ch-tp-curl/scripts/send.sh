#!/bin/sh
~>curl -s --user 'api:key-@@sample:[a-f0-9]{32}@@' \
  https://api.mailgun.net/v3/mg.acme.example/messages \
  -F from='ops@acme.example' -F to='team@acme.example' -F text='done'
