<?php
class Token
{
    private const CIPHER = 'AES-128-CBC';

    public function open(string $blob, string $key): string|false
    {
        $raw = base64_decode($blob);
        $iv = substr($raw, 0, 16);
~>        return openssl_decrypt(substr($raw, 16), self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
    }
}
