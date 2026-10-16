<?php
$nonce = random_bytes(12);
$ct = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
$pt = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
