<?php
use phpseclib3\Crypt\TripleDES;

function seal($data, $key, $iv) {
~>    return openssl_encrypt($data, 'des-ede3-cbc', $key, OPENSSL_RAW_DATA, $iv);
}

function fish($data, $key, $iv) {
~>    return openssl_decrypt($data, "BF-CBC", $key, OPENSSL_RAW_DATA, $iv);
}

function configured($data, $key) {
    $method = 'rc4';
~>    return openssl_encrypt($data, $method, $key);
}

function legacy_mcrypt($data, $key, $iv) {
~>    return mcrypt_encrypt(MCRYPT_3DES, $key, $data, MCRYPT_MODE_CBC, $iv);
}

function with_phpseclib($data, $key) {
~>    $c = new TripleDES('cbc');
    $c->setKey($key);
    return $c->encrypt($data);
}
