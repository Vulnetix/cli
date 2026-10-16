<?php

function legacy_sync(string $user, string $pass): array
{
~>    $url = "https://legacy.example.com/api/export?user=$user&passwd=$pass";
    $body = file_get_contents($url);
    if ($body === false) {
        return [];
    }
    return json_decode($body, true) ?? [];
}
