<?php
function old_encrypt($key, $data, $iv)
{
~>    return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
}

function old_decrypt($key, $data, $iv)
{
~>    return mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $data, 'cbc', $iv);
}
