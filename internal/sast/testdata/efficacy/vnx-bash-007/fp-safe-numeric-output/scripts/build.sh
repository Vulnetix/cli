#!/bin/bash
sleep $((ATTEMPT * 5))
for job in $(jobs -p); do wait "$job"; done
chown $(id -u):$(id -g) /data
docker build -t app:$(git rev-parse --short HEAD) .
make -j$(nproc)
touch backup-$(date +%Y%m%d).tgz
if (( $(wc -l < file.txt) > 10 )); then :; fi
case $(uname -s) in
  Linux) echo linux ;;
esac
for i in $(seq 1 5); do echo "$i"; done
