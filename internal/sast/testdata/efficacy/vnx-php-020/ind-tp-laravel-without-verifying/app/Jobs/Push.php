<?php

namespace App\Jobs;

use Illuminate\Support\Facades\Http;

class Push
{
    public function handle(string $url, array $payload)
    {
~>        Http::withoutVerifying()->post($url, $payload);
    }
}
