<?php
$target = $_REQUEST["target"];
~>$ch = curl_init($target);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$body = curl_exec($ch);

$endpoint = trim($_GET["endpoint"]);
$ch2 = curl_init();
~>curl_setopt($ch2, CURLOPT_URL, $endpoint);
~>curl_setopt($ch2, CURLOPT_URL, $_COOKIE["callback"]);
