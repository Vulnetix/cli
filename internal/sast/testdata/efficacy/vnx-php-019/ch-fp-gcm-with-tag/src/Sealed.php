<?php
class Sealed
{
    public function seal($plain, $key, $iv, &$tag)
    {
        return openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    }

    public function chacha($plain, $key, $iv, &$tag)
    {
        return openssl_encrypt($plain, 'chacha20-poly1305', $key, OPENSSL_RAW_DATA, $iv, $tag);
    }
}
