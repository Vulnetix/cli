<?php

namespace App\Http;

class Csrf
{
    public static function issue(): string
    {
        if (empty($_SESSION['csrf_token'])) {
~>            $_SESSION['csrf_token'] = sha1(uniqid((string) mt_rand(), true));
        }
        return $_SESSION['csrf_token'];
    }
}
