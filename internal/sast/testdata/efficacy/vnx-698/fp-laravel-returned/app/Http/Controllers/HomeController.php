<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class HomeController extends Controller
{
    public function index(Request $request)
    {
        if (! $request->user()) {
            return redirect('/login');
        }
        $to = redirect()->route('home');
        return $to;
    }
}
