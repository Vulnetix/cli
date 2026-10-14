<?php
$ctx = stream_context_create([
    'ssl' => [
~>        'verify_peer' => false,
~>        'verify_peer_name' => false,
    ],
]);
$data = file_get_contents('https://feeds.example.net/rates.json', false, $ctx);
