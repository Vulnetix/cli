#!/bin/sh
set -eu
curl -fsS -X POST \
~>  -H "Authorization: Basic @@sample:a[m]Vu[a]2l[u]cz[o]0Z[k]c3[a]FE[y]a0[x]tO[V]A[=]@@" \
  -F "file=@build/app.tar.gz" \
  https://artifacts.internal.example.net/upload
