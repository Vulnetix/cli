<?php
$missing = [];
if (extension_loaded('mcrypt')) {
    $warnings[] = 'The mcrypt extension is loaded; it is unmaintained and should be removed.';
}
if (defined('MCRYPT_RIJNDAEL_128')) {
    $warnings[] = "mcrypt constants found; migrate calls such as mcrypt_encrypt() to openssl_encrypt()";
}
$disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
$mcryptDisabled = in_array('mcrypt_decrypt', $disabled, true);
$help = <<<TXT
Replace mcrypt_encrypt(MCRYPT_RIJNDAEL_128, \$k, \$d, MCRYPT_MODE_CBC, \$iv)
with sodium_crypto_secretbox(\$d, \$nonce, \$k).
TXT;
// mcrypt_module_open('rijndael-256', '', 'ofb', '') was removed in PHP 7.2
