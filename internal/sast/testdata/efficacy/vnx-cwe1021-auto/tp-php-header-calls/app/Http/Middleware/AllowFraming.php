<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class AllowFraming
{
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);
~>        $response->headers->remove('X-Frame-Options');
~>        $response->headers->set('X-Frame-Options', 'ALLOW-FROM https://portal.example.com');

        return $response;
    }
}
