<?php
function seal($plain, $encKey, $macKey) {
    $iv = random_bytes(16);
    $ct = openssl_encrypt($plain, 'aes-256-cbc', $encKey, OPENSSL_RAW_DATA, $iv);
    $mac = hash_hmac('sha256', $iv . $ct, $macKey, true);
    return $mac . $iv . $ct;
}
