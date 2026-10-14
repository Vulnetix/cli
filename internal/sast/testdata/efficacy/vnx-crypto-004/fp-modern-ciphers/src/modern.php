<?php

function seal($data, $key) {
    $iv = random_bytes(12);
    $ct = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return $iv . $tag . $ct;
}

function describe($designation) {
    return "Designation: " . $designation;
}
