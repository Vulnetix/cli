<?php
use phpseclib3\Crypt\AES;

function encrypt_token($plaintext, $key) {
~>    return openssl_encrypt($plaintext, 'aes-128-ecb', $key, OPENSSL_RAW_DATA);
}

function decrypt_token($ciphertext, $key) {
~>    return openssl_decrypt($ciphertext, "AES-256-ECB", $key, OPENSSL_RAW_DATA);
}

function configured($data, $key) {
    $method = 'aes-128-ecb';
~>    return openssl_encrypt($data, $method, $key);
}

function legacy_mcrypt($data, $key) {
~>    return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_ECB);
}

function with_phpseclib($data, $key) {
~>    $cipher = new AES('ecb');
    $cipher->setKey($key);
    return $cipher->encrypt($data);
}
