<?php

namespace App\Http\Controllers;

class ProfileController extends Controller
{
    public function update(Request $request)
    {
        $user = $request->user();
~>        $user->secret = base64_encode($request->input('password'));
        $user->save();
        return redirect('/profile');
    }
}
