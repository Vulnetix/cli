#!/bin/sh
sudo -u postgres psql -c 'select 1'
docker run -u appuser:appgroup acme/app
echo hi | su -u nobody:Passw0rdX9zQ
curl -sS https://acme-corp.io/ | tee out.txt
