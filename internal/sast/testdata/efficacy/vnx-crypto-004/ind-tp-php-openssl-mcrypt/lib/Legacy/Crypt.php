<?php

class LegacyCrypt
{
    public function encode(string $data, string $key, string $iv): string
    {
~>        return openssl_encrypt($data, 'bf-cbc', $key, OPENSSL_RAW_DATA, $iv);
    }

    public function oldEncode(string $data, string $key, string $iv): string
    {
~>        return mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_CBC, $iv);
    }
}
