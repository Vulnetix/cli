<?php
function make_token($key, $payload)
{
~>    return base64_encode(mcrypt_encrypt(MCRYPT_BLOWFISH, $key, $payload, MCRYPT_MODE_ECB));
}

function read_token($key, $token)
{
~>    $plain = mcrypt_decrypt (
        MCRYPT_BLOWFISH,
        $key,
        base64_decode($token),
        MCRYPT_MODE_ECB
    );
    return rtrim($plain, "\0");
}
