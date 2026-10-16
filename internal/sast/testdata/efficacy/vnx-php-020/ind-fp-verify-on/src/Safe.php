<?php
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
curl_setopt($ch, CURLOPT_CAINFO, '/etc/ssl/certs/internal-ca.crt');
$client = new \GuzzleHttp\Client(['verify' => '/etc/ssl/certs/internal-ca.crt']);
$ctx = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
