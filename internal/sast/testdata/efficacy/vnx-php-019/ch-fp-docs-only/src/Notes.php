<?php
// Old code used openssl_encrypt($data, 'aes-256-cbc', $key) with no MAC; do not bring it back.
/* openssl_decrypt($ct, 'aes-128-cbc', $k, 0, $iv); */
$warning = "openssl_encrypt(\$x, 'aes-256-cbc', \$k) is unauthenticated";
echo $warning;
