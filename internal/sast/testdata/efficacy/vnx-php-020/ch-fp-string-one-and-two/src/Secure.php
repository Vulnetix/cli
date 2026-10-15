<?php
$ch = curl_init('https://api.example.com');
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, "1");
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, '2');
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
curl_setopt($ch, CURLOPT_CAINFO, '/etc/ssl/certs/ca-bundle.crt');
