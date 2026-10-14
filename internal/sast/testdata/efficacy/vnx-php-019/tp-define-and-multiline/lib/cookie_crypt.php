<?php
define('COOKIE_CIPHER', 'camellia-256-cbc');

function encrypt_cookie($value, $key)
{
    $iv = openssl_random_pseudo_bytes(16);
~>    $enc = openssl_encrypt(
        $value,
        COOKIE_CIPHER,
        $key,
        0,
        $iv
    );
    setcookie('prefs', base64_encode($iv) . ':' . $enc);
}
