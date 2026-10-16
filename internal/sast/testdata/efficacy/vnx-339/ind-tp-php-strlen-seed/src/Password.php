<?php

function generate_password(string $email): string
{
~>    mt_srand(strlen($email));
    $password = '';
    for ($i = 0; $i < 12; $i++) {
        $password .= chr(mt_rand(33, 126));
    }
    return $password;
}
