<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;

class WebhookTester
{
    public function ping($request)
    {
        $hook = $request->input("webhook_url");
~>        $response = Http::timeout(5)->post($hook, ["ping" => true]);
~>        $res = $this->client->request("GET", $request->query("probe"));
        $httpClient = new \GuzzleHttp\Client();
~>        $httpClient->get($hook);
        return $response->status();
    }
}
