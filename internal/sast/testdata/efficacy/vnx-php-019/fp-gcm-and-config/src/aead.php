<?php
$config = [
    'cipher' => 'AES-256-CBC',
    'key' => getenv('APP_KEY'),
];
function seal($data, $key)
{
    $iv = random_bytes(12);
    $ct = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return $iv . $tag . $ct;
}
$c = openssl_encrypt($payload, 'chacha20-poly1305', $k, OPENSSL_RAW_DATA, $nonce, $tag);
$composite = openssl_encrypt($payload, 'aes-128-cbc-hmac-sha256', $k, OPENSSL_RAW_DATA, $iv);
