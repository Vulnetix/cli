<?php

namespace App\Services;

use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;

class PartnerApi
{
    public function client(): Client
    {
        return new Client([
            'base_uri' => 'https://partner.example.com',
~>            RequestOptions::VERIFY => false,
        ]);
    }

    public function ping()
    {
~>        return $this->client()->request('GET', '/ping', ['verify' => false, 'timeout' => 5]);
    }
}
