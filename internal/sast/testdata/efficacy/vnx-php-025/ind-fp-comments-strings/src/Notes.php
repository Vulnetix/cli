<?php
// TODO: replace mcrypt_encrypt($k, $d) with sodium
/* mcrypt_decrypt was removed in PHP 7.2 */
$msg = "Do not call mcrypt_decrypt() any more";
$doc = 'mcrypt_module_open is gone';
$ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
$box = sodium_crypto_secretbox($plain, $nonce, $key);
