<?php

function seal(string $plain, string $key): string
{
    $iv = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
    $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return base64_encode($iv . $tag . $ct);
}

function derive(string $pw, string $salt): string
{
    return hash_pbkdf2('sha256', $pw, $salt, 600000, 64);
}

function ecb(string $plain, string $key): string
{
    return openssl_encrypt($plain, 'aes-128-ecb', $key, OPENSSL_RAW_DATA);
}
