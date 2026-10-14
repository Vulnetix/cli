<?php

function seal($data, $key) {
    $iv = random_bytes(12);
    $ct = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return $iv . $tag . $ct;
}

function sodium_seal($data, $key) {
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return $nonce . sodium_crypto_secretbox($data, $nonce, $key);
}
