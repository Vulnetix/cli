#!/bin/sh
VERSION="$1"
cd /tmp || exit 1
curl -fsSLO "https://releases.example.com/app-${VERSION}.tar.gz"
curl -fsSLO "https://releases.example.com/app-${VERSION}.tar.gz.asc"
~>gpg --verify "app-${VERSION}.tar.gz.asc" "app-${VERSION}.tar.gz"
tar -xzf "app-${VERSION}.tar.gz" -C /opt/app
systemctl restart app
