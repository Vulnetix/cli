<?php

function make_key()
{
    $config = [
        'digest_alg' => 'sha256',
~>        'private_key_bits' => 1024,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];
    return openssl_pkey_new($config);
}

function make_dsa()
{
~>    return openssl_pkey_new(array("private_key_bits" => 512, "private_key_type" => OPENSSL_KEYTYPE_DSA));
}
