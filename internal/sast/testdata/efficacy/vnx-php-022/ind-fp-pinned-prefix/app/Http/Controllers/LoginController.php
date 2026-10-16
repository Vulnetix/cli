<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class LoginController extends Controller
{
    public function show(Request $request)
    {
        return redirect('/login?next=' . urlencode($request->input('next')));
    }
}
