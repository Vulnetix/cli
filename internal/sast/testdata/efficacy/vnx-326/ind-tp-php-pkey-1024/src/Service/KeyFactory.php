<?php

namespace App\Service;

class KeyFactory
{
    public function create()
    {
~>        return openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    }
}
