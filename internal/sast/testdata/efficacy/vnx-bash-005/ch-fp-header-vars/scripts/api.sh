#!/bin/bash
curl -s -H "Authorization: Bearer $TOKEN" https://api.example.org/v1/items
curl -s -H "Authorization: Bearer ${API_TOKEN}" https://api.example.org/v1/items
curl -s -H "Content-Type: application/json" https://api.example.org/v1/items
docker login -u "$U" -p "$P" registry.example.com
redis-cli -h cache -a "$REDIS_PASS" ping
PGPASSWORD="$DB_PASS" psql -h db -U app
OLDPWD=/tmp
