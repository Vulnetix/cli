<?php
namespace App;

class Vault
{
    public function encrypt(string $plain, string $key): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return $nonce . sodium_crypto_secretbox($plain, $nonce, $key);
    }

    public function legacy(string $plain, string $key, string $iv): string
    {
        return openssl_encrypt($plain, 'aes-256-cbc', $key, 0, $iv);
    }
}
