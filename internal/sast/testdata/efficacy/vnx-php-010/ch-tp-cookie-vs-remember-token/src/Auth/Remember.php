<?php
namespace App\Auth;

class Remember
{
    public function check(array $user): bool
    {
~>        if ($_COOKIE['remember'] == $user['remember_token']) {
            return true;
        }
        return false;
    }
}
