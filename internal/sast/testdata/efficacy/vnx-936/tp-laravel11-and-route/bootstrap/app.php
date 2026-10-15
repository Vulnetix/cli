<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: __DIR__.'/../routes/web.php')
    ->withMiddleware(function (Middleware $middleware) {
~>        $middleware->web(remove: [ValidateCsrfToken::class]);
~>        $middleware->validateCsrfTokens(except: ['*']);
    })
    ->create();
