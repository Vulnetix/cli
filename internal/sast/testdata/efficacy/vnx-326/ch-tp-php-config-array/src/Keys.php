<?php

namespace Acme;

final class Keys
{
    public static function generate()
    {
        $config = [
            'digest_alg' => 'sha256',
~>            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        return openssl_pkey_new($config);
    }
}
