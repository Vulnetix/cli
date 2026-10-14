<?php
$ch = curl_init('https://api.example.com/v1/items');
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
curl_setopt($ch, CURLOPT_CAINFO, __DIR__ . '/certs/ca-bundle.pem');
$client = new \GuzzleHttp\Client(['verify' => __DIR__ . '/certs/ca-bundle.pem']);
$other = new \GuzzleHttp\Client(['verify' => true]);
$ctx = stream_context_create(['ssl' => ['verify_peer' => true, 'cafile' => '/etc/ssl/certs/ca.pem']]);
