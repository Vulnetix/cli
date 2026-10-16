#!/usr/bin/env bash
sort -k 2 -t, data.csv | head -20
curl -K ./curl.conf https://api.example.com/report
curl --key ./client.key --cert ./client.pem https://mtls.example.com/
ls -k /tmp > /dev/null
