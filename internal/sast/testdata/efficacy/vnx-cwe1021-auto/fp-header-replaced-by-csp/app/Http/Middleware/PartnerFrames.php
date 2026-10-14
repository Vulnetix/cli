<?php

namespace App\Http\Middleware;

class PartnerFrames
{
    public function handle($request, \Closure $next)
    {
        $response = $next($request);
        $response->headers->remove('X-Frame-Options');
        $response->headers->set('Content-Security-Policy', "frame-ancestors 'self' https://cms.example.org");

        return $response;
    }
}
