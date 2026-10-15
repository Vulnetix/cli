<?php

namespace App\Services;

class Invites
{
    public function create(): array
    {
~>        mt_srand(20240101);
        $inviteCode = mt_rand(100000, 999999);

~>        $engine = new \Random\Engine\Mt19937(42);
        $randomizer = new \Random\Randomizer($engine);
        $apiKey = bin2hex($randomizer->getBytes(16));

        return [$inviteCode, $apiKey];
    }
}
