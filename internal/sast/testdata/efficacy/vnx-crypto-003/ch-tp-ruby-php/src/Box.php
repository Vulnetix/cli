<?php
function seal($data, $key) {
~>    return openssl_encrypt($data, 'AES-128-ECB', $key, OPENSSL_RAW_DATA);
}
