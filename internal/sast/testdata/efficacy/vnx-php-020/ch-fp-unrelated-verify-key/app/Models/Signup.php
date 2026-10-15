<?php

namespace App\Models;

class Signup
{
    public function defaults(): array
    {
        return ['email' => '', 'email_verified' => false, 'verified' => false];
    }
}
