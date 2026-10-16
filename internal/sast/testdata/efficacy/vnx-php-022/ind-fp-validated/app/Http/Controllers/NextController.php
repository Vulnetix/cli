<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class NextController extends Controller
{
    public function go(Request $request)
    {
        $next = $request->input('next', '/dashboard');
        if (!preg_match('#^/[a-zA-Z0-9/_-]*$#', $next)) {
            $next = '/dashboard';
        }
        return redirect($next);
    }
}
