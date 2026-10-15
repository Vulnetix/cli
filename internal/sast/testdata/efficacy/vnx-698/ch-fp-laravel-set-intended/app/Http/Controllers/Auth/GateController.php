<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;

class GateController extends Controller
{
    public function remember(Request $request)
    {
        redirect()->setIntendedUrl($request->fullUrl());
        Redirect::setIntendedUrl('/dashboard');
        return view('auth.login');
    }
}
