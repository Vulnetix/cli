<?php
// We migrated away from openssl_encrypt($d, 'aes-256-cbc', $k) to sodium.
$box = sodium_crypto_secretbox($msg, $nonce, $key);
