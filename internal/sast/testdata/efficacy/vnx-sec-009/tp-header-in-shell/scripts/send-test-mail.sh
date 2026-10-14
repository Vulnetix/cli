#!/bin/sh
curl --request POST \
  --url https://api.sendgrid.com/v3/mail/send \
~>  --header "Authorization: Bearer @@sample:SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}@@" \
  --header 'Content-Type: application/json' \
  --data @payload.json
