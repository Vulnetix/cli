<?php

namespace App\Client;

use Symfony\Component\HttpClient\HttpClient;

class InsecureClient
{
    public static function create()
    {
        return HttpClient::create([
~>            'verify_peer' => false,
~>            'verify_peer_name' => FALSE,
        ]);
    }
}
