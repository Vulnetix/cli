<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;

class AuthController extends Controller
{
    public function login(Request $request)
    {
~>        return redirect($request->input('next'));
    }

    public function logout(Request $request)
    {
        $return = $request->query('return');
~>        return redirect()->to($return);
    }

    public function out()
    {
~>        return Redirect::away(request('url'));
    }

    public function legacy()
    {
~>        return Redirect::to(\Input::get('continue'));
    }
}
