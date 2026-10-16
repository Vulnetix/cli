<?php
$ch = curl_init('https://api.partner.example/v1/orders');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
~>curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$body = curl_exec($ch);
curl_close($ch);
