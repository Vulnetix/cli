#!/bin/sh
curl -fsS \
  -X PUT \
~>  -u 'uploader:Kp4wQ8zN2rTx' \
  --data-binary @app.jar \
  https://maven.acme-corp.io/releases/app.jar
