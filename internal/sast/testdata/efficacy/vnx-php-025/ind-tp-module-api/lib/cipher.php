<?php
function encrypt_record($key, $data)
{
~>    $td = mcrypt_module_open(MCRYPT_3DES, '', MCRYPT_MODE_CFB, '');
    $ivSize = mcrypt_enc_get_iv_size($td);
~>    $iv = mcrypt_create_iv($ivSize, MCRYPT_DEV_URANDOM);
    mcrypt_generic_init($td, $key, $iv);
~>    $enc = mcrypt_generic($td, $data);
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
    return $iv . $enc;
}
