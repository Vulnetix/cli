<?php
class Backup
{
    public function encryptArchive($bytes, $key, $iv)
    {
~>        $encrypted = openssl_encrypt(
            $bytes,
            'aes-192-cbc',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
        return $encrypted;
    }
}
