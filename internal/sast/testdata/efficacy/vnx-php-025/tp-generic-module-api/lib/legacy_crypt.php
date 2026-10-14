<?php

function legacy_encrypt($data, $key)
{
~>    $td = mcrypt_module_open(MCRYPT_BLOWFISH, '', MCRYPT_MODE_CBC, '');
    $iv = random_bytes(mcrypt_enc_get_iv_size($td));
    mcrypt_generic_init($td, $key, $iv);
~>    $cipher = mcrypt_generic($td, $data);
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
    return $iv . $cipher;
}

function legacy_decrypt($blob, $key)
{
~>    $td = mcrypt_module_open('tripledes', '', 'ecb', '');
    mcrypt_generic_init($td, $key, str_repeat("\0", 8));
~>    $plain = mdecrypt_generic($td, $blob);
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
    return $plain;
}
