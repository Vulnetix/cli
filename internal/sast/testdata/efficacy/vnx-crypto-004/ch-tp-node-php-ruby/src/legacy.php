<?php
function seal($data, $key, $iv) {
~>    return openssl_encrypt($data, "des-ede3-cbc", $key, 0, $iv);
}
function seal2($data, $key, $iv) {
~>    return mcrypt_encrypt(MCRYPT_BLOWFISH, $key, $data, MCRYPT_MODE_CBC, $iv);
}
