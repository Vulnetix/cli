#!/bin/sh
if ! sha256sum -c app.tar.gz.sha256; then
  echo "checksum mismatch" >&2
  exit 1
fi
tar -xzf app.tar.gz

sha256sum -c plugin.sha256 || exit 1
gpg --verify app.asc app.tar.gz && tar -xzf app.tar.gz
echo "$SUM  tool" | sha256sum -c - || { echo "bad sum"; exit 1; }

shasum -a 256 -c sums.txt
if [ $? -ne 0 ]; then exit 1; fi

sha256sum app.tar.gz > app.tar.gz.sha256

verify_sig() {
  gpg --verify "$1.asc" "$1"
}
verify_sig app.tar.gz || exit 1
cosign verify-blob --key k.pub --signature a.sig a
