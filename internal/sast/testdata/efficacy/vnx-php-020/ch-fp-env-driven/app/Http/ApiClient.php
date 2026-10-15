<?php

namespace App\Http;

use Illuminate\Support\Facades\Http;

class ApiClient
{
    public function get(string $url)
    {
        return Http::withOptions([
            'verify' => env('HTTP_VERIFY_TLS', true),
        ])->get($url);
    }

    public function curl($ch)
    {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->verifyPeer);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, config('http.verify_host') ? 2 : 0);
    }
}
