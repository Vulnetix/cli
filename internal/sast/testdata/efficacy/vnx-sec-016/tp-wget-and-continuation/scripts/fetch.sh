#!/bin/sh
~>wget --no-check-certificate https://mirror.example.com/pkg.deb
~>wget -q --no-check-certificate -O- "$URL" > out.bin

curl -fsSL \
  -H "Authorization: Bearer $TOKEN" \
~>  --insecure \
  https://api.example.com/upload
