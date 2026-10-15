<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
    // Never put '*' here: it turns CSRF protection off.
    protected $except = [
        'stripe/webhook',
        'api/github/*',
    ];
}
