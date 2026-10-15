<?php
~>ini_set('session.cookie_httponly', '0');
session_start();

function remember_user(string $token): void
{
~>    setcookie('remember_token', $token, time() + 86400 * 30, '/', '', true, false);
}
