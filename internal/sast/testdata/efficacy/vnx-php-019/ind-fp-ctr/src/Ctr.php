<?php
$iv = random_bytes(16);
$out = openssl_encrypt($data, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $iv);
