<?php
namespace App\Http\Middleware;

class ApiToken
{
    public function handle($request, $next)
    {
        $user = $this->users->find($request->input('user_id'));
~>        if ($request->input('token') == $user->api_token) {
            return $next($request);
        }
        abort(401);
    }
}
