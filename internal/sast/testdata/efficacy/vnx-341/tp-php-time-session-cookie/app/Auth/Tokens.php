<?php

function issue($user)
{
~>    $token = hash('sha256', $user . time());
~>    $session_id = md5($_SERVER['REMOTE_ADDR'] . microtime());
~>    $stamp = microtime(true);
    $csrf = sha1($stamp);
    return [$token, $session_id, $csrf];
}
