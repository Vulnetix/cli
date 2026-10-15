#!/bin/sh
set -eu
~>curl -T dist.tar.gz ftp://uploader:h3Lp8sQz2Vx@@@sample:f[t]p[.][a]cm[e][-]c[o]rp[.]io[/]in[c]om[i]ng[/]@@
~>lftp -e "put dist.zip; bye" sftp://release:Wr4kT9zPq2@@@sample:f[i]le[s][.]a[c]me[-]co[r]p[.][i]o@@
