<?php

namespace App\Services;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Http;

class PaymentGateway
{
    public function client()
    {
~>        return new Client(['base_uri' => config('pay.url'), 'verify' => false]);
    }

    public function charge(array $payload)
    {
        $response = $this->client()->request('POST', '/charges', [
            'json' => $payload,
~>            'verify' => false,
        ]);
        return json_decode((string) $response->getBody(), true);
    }

    public function refund($id)
    {
~>        return Http::withoutVerifying()->post(config('pay.url') . '/refunds/' . $id);
    }

    public function status($id)
    {
~>        return Http::withOptions(['verify' => false])->get(config('pay.url') . '/charges/' . $id);
    }
}
