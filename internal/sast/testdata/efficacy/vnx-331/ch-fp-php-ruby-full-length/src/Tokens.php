<?php

function issue_reset_token(): string
{
    $resetToken = bin2hex(random_bytes(32));
    $file_name = bin2hex(random_bytes(4)) . '.png';
    $iv = openssl_random_pseudo_bytes(12);
    return $resetToken;
}
