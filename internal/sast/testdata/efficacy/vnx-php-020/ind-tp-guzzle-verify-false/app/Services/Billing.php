<?php

namespace App\Services;

use GuzzleHttp\Client;

class Billing
{
    public function client(): Client
    {
~>        return new Client(['base_uri' => config('billing.url'), 'timeout' => 10, 'verify' => false]);
    }
}
