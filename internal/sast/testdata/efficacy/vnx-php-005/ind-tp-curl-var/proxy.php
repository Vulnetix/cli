<?php
$endpoint = trim($_GET["endpoint"]);
$ch = curl_init();
~>curl_setopt($ch, CURLOPT_URL, $endpoint);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
echo curl_exec($ch);
