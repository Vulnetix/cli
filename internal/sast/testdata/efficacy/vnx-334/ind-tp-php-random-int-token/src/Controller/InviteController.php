<?php

namespace App\Controller;

class InviteController
{
    public function create(array $data): array
    {
~>        $inviteToken = random_int(100000, 999999);
~>        $apiKey = mt_rand(1, 99999999);
        return ['invite' => $inviteToken, 'key' => $apiKey];
    }
}
