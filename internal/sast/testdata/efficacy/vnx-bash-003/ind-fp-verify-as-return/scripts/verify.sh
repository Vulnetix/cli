#!/bin/sh
verify_download() {
  gpg --verify "$1.sig" "$1"
}

verify_download app.bin && install -m 0755 app.bin /usr/local/bin/app
sha256sum -c app.bin.sha256
