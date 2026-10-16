<?php
$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 15,
~>    CURLOPT_SSL_VERIFYHOST => 0,
]);
$out = curl_exec($ch);
