<?php
function decrypt_legacy($key, $iv, $data)
{
    if (!function_exists('mcrypt_decrypt')) {
        throw new RuntimeException('no mcrypt');
    }
~>    return call_user_func('mcrypt_decrypt', MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
}
