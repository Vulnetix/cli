<?php
function seal(string $data, string $key): string
{
    $iv = random_bytes(16);
~>    $ct = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $ct);
}

function unseal(string $blob, string $key)
{
    $raw = base64_decode($blob);
~>    return openssl_decrypt(substr($raw, 16), "AES-128-CBC", $key, OPENSSL_RAW_DATA, substr($raw, 0, 16));
}

function legacy_alias($d, $k, $iv)
{
~>    return \openssl_encrypt($d, 'aes256', $k, 0, $iv);
}
