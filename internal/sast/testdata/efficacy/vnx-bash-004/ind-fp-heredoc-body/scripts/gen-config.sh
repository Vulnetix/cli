#!/bin/bash
host="$1"
cat > /etc/app/app.conf <<CONF
listen $host
upstream $1
CONF
echo configured $host
