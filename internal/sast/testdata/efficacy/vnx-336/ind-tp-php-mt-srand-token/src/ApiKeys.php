<?php

namespace App\Security;

class ApiKeys
{
    public function issue(int $userId): string
    {
~>        mt_srand(31337);
        $apiKey = '';
        for ($i = 0; $i < 32; $i++) {
            $apiKey .= dechex(mt_rand(0, 15));
        }
        return $apiKey;
    }
}
