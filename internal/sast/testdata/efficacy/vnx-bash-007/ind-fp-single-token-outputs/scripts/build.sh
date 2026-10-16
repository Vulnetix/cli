#!/bin/bash
make -j$(nproc) all
chown $(id -u):$(id -g) ./dist
kill $(jobs -p) 2>/dev/null
docker build -t app:$(git rev-parse --short HEAD) .
mkdir -p logs/$(date +%Y%m%d)
for i in $(seq 1 5); do curl -fsS http://localhost:8080/health && break; sleep "$i"; done
