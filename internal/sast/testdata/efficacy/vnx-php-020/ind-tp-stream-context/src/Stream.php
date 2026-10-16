<?php
$ctx = stream_context_create([
    'ssl' => [
~>        'verify_peer' => false,
        'verify_peer_name' => true,
    ],
]);
$data = file_get_contents('https://feeds.example.net/data.json', false, $ctx);
