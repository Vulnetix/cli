<?php
class Crypto
{
    public function seal(string $plain, string $key): string
    {
        $iv = random_bytes(16);
~>        $ct = openssl_encrypt($plain, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $ct);
    }
}
