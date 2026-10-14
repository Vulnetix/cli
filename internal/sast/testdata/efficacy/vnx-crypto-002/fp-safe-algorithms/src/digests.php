<?php

function checksum($data) {
    return hash('sha256', $data);
}

function sign($payload, $key) {
    openssl_sign($payload, $sig, $key, OPENSSL_ALGO_SHA256);
    return $sig;
}
