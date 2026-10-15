<?php

function reset_link(string $email): string
{
~>    $reset_code = md5($_SERVER['REMOTE_ADDR'] . time());
    store_code($email, $reset_code);
    return "/reset?code=" . $reset_code;
}
