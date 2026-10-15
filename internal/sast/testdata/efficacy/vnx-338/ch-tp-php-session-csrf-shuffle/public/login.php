<?php
session_start();
~>$_SESSION['csrf_token'] = md5(rand());
$chars = '@@sample:a[b]cd[e]fg[h]ij[k]lm[n]op[q]rs[t]uv[w]xy[z]01[2]34[5]67[8]9@@';
~>$apiKey = substr(str_shuffle($chars), 0, 32);
