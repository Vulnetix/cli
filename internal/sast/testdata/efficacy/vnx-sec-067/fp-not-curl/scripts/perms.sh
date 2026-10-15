#!/bin/sh
sudo -u www-data:www-data ls /var/www
docker run -u app:Kq8Zr2Lw alpine id && curl -fsS https://acme-corp.io
curl -fsS https://get.acme-corp.io/install.sh | sudo -u deploy:wheel9staff sh
