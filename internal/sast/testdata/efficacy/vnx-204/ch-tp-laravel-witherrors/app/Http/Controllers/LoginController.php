<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        $user = User::where('email', $request->input('email'))->first();
        if (! $user) {
~>            return back()->withErrors(['email' => 'This email is not registered.']);
        }
        if (! Hash::check($request->input('password'), $user->password)) {
            return back()->withErrors(['password' => 'The password is incorrect.']);
        }
        auth()->login($user);
        return redirect('/home');
    }
}
