<?php

function claims($id)
{
    $payload = ['sub' => $id, 'iat' => time(), 'exp' => time() + 3600];
    $_SESSION['login_time'] = time();
    $cookie_value = bin2hex(random_bytes(20));
    setcookie("dvwaSession", $cookie_value, time() + 3600, "/");
    $token = bin2hex(random_bytes(32));
    $tokenCreated = time();
    return [$payload, $token, $tokenCreated];
}
