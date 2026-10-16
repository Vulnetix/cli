<?php
$method = 'aes-192-cbc';
$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));
~>$enc = openssl_encrypt(json_encode($payload), $method, $secret, 0, $iv);
setcookie('state', base64_encode($iv) . ':' . $enc);
