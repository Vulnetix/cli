<?php
// openssl_encrypt($data, 'aes-256-cbc', $key) is unauthenticated
$hint = "use openssl_encrypt(\$d, 'aes-256-cbc', ...) only with an HMAC";
function wrap($data, $key, $iv)
{
    return openssl_encrypt($data, $this->cipher, $key, 0, $iv);
}
$methods = array_filter(openssl_get_cipher_methods(), fn($m) => str_ends_with($m, '-cbc'));
