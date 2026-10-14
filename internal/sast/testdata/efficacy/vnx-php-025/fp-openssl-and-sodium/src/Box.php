<?php

final class Box
{
    public function seal(string $plain, string $key): string
    {
        $nonce = random_bytes(12);
        $tag = '';
        $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
        return $nonce . $tag . $ct;
    }

    public function sodiumSeal(string $plain, string $key): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return $nonce . sodium_crypto_secretbox($plain, $nonce, $key);
    }

    public function sodiumOpen(string $box, string $nonce, string $key)
    {
        return sodium_crypto_secretbox_open($box, $nonce, $key);
    }
}
