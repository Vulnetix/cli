<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;
use Symfony\Component\HttpFoundation\RedirectResponse;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        $returnTo = $request->input("return_to");
        if (auth()->attempt($request->only("email", "password"))) {
~>            return redirect($returnTo);
        }
~>        return redirect()->away($request->query("fallback"));
    }

    public function legacy(Request $request)
    {
~>        return Redirect::to($request->get("u"));
    }

    public function sso(Request $request)
    {
        $target = $request->query->get("target");
~>        return new RedirectResponse($target);
    }
}
