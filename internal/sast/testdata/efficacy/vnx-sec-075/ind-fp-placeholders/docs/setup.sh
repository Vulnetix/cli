#!/bin/sh
wg set wg0 private-key /etc/wireguard/private.key
cat > /etc/wireguard/wg2.conf <<EOT
[Interface]
PrivateKey = <your-private-key>
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PrivateKey = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=
EOT
