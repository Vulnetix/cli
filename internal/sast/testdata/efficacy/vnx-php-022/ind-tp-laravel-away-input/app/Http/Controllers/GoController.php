<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class GoController extends Controller
{
    public function out(Request $request)
    {
~>        return redirect()->away($request->input('url'));
    }
}
