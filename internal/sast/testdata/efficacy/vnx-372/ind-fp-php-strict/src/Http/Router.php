<?php

namespace App\Http;

class Router
{
    public function isApi(string $uri): bool
    {
        if (strpos($uri, '/api/') !== false) {
            return true;
        }
        if (str_contains($uri, '/graphql')) {
            return true;
        }
        return strpos($uri, '/v2/') === 0;
    }

    public function describe(): string
    {
        return "use strpos(\$a, \$b) == false carefully";
    }
}
