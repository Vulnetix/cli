<?php

namespace App\Auth;

class RememberMe
{
    public function issue(int $userId): string
    {
~>        $token = bin2hex(random_bytes(6));
        setcookie('remember', $userId . ':' . $token, time() + 86400 * 30, '/', '', true, true);
        return $token;
    }
}
