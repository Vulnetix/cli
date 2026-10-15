<?php
function seal($d, $k) {
~>    return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $k, $d, MCRYPT_MODE_ECB);
}
