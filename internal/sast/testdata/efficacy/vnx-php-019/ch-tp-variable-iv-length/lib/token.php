<?php
function make_token($plain, $key)
{
    $cipher = "aes-128-cbc";
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($cipher));
~>    $ct = openssl_encrypt($plain, $cipher, $key, 0, $iv);
    return base64_encode($iv . $ct);
}
