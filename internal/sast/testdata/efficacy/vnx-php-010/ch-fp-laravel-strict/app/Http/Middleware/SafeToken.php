<?php
namespace App\Http\Middleware;

class SafeToken
{
    public function handle($request, $next)
    {
        if (hash_equals((string) $user->api_token, (string) $request->input('token'))) {
            return $next($request);
        }
        if ($request->input('mode') == 'dark') {
            $theme = 'dark';
        }
        abort(401);
    }
}
