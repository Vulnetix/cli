#!/bin/sh
curl -sS http://localhost:9200/_cluster/health -u elastic
curl --negotiate -u : https://kerberos.acme.io/
curl --netrc-file ~/.netrc -u deploy https://files.acme.io/
