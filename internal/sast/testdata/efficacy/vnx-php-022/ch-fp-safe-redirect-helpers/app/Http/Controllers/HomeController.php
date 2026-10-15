<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class HomeController
{
    public function index(Request $request)
    {
        if ($request->user() === null) {
            return redirect()->route('login', ['next' => $request->path()]);
        }

        return redirect()->intended('/dashboard');
    }

    public function cancel(Request $request)
    {
        return redirect()->back()->withInput($request->except('password'));
    }
}

function legacy_return() {
	wp_safe_redirect( $_GET['redirect_to'] );
	exit;
}
