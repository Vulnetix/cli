<?php
$algos = hash_algos(); // includes md5
$mac = hash_hmac('md5', $payload, $key);
$h = hash('sha256', $payload);
