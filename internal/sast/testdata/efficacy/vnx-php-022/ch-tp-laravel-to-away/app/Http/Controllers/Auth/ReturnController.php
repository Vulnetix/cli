<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;

class ReturnController
{
    public function afterLogin(Request $request)
    {
~>        return redirect()->to($request->query('return_to'));
    }

    public function external(Request $request)
    {
~>        return Redirect::away($request->input('url'));
    }

    public function back(Request $request)
    {
~>        return redirect($request->get('next'));
    }
}
