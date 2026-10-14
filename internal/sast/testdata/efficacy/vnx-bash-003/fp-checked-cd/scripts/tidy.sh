#!/bin/bash
# Every cd is checked before anything is deleted.
cd "$BUILD_DIR" || exit 1
rm -rf ./*

cd /opt/app/cache && rm -rf ./*

if ! cd "$WORKDIR"; then
  echo "no workdir" >&2
  exit 1
fi
rm -rf tmp

cd "$STAGING" || { echo "missing staging dir" >&2; exit 1; }
find . -name '*.tmp' -delete

cd "$OUT"
if [ $? -ne 0 ]; then exit 1; fi
rm -f ./*.o

cd "$(dirname "$0")"
./build.sh
cd ..
make dist

cd /var/log/app
rm -f /var/log/app/old.log

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
