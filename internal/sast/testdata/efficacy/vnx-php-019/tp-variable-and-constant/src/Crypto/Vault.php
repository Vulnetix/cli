<?php
namespace App\Crypto;

class Vault
{
    const CIPHER = 'AES-256-CBC';

    private $key;

    public function lock($plain)
    {
        $iv = random_bytes(openssl_cipher_iv_length(self::CIPHER));
~>        return $iv . openssl_encrypt($plain, self::CIPHER, $this->key, OPENSSL_RAW_DATA, $iv);
    }

    public function unlock($payload)
    {
        $method = 'aes-192-cbc';
~>        return openssl_decrypt(substr($payload, 16), $method, $this->key, OPENSSL_RAW_DATA, substr($payload, 0, 16));
    }
}
