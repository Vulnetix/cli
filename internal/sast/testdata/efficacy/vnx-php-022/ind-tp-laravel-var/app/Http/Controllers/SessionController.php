<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class SessionController extends Controller
{
    public function store(Request $request)
    {
        $return = $request->query('return');
        // authenticate ...
~>        return redirect()->to($return);
    }
}
