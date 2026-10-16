<?php
function seal($pub, $data) {
~>    openssl_public_encrypt($data, $out, $pub);
    return $out;
}
