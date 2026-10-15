<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class LoginController extends Controller
{
    public function store(Request $request)
    {
~>        $ip = $request->header('X-Forwarded-For') ?? $request->ip();
        RateLimiter::hit('login:' . $ip);
        return redirect('/');
    }
}
