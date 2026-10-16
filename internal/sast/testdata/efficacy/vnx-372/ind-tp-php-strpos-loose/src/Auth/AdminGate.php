<?php

namespace App\Auth;

class AdminGate
{
    public function isAdmin(string $email): bool
    {
~>        if (strpos($email, 'admin@') == false) {
            return false;
        }
        return true;
    }

    public function isInternal(string $host): bool
    {
~>        return stripos($host, 'corp.example') ? true : false;
    }
}
