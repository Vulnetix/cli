<?php

// mcrypt_encrypt() was removed in PHP 7.2; we use openssl_encrypt() instead.
/*
 * Old code: $c = mcrypt_decrypt(MCRYPT_DES, $k, $d, MCRYPT_MODE_ECB);
 */
# mcrypt_generic($td, $data) is gone too.

function crypto_report(): array
{
    return [
        'mcrypt' => extension_loaded('mcrypt'),
        'legacy' => function_exists('mcrypt_encrypt'),
        'hint' => "Replace mcrypt_encrypt( with openssl_encrypt(",
    ];
}

$ct = openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag); // not mcrypt_encrypt($data)
$size = openssl_cipher_iv_length('aes-256-cbc');
