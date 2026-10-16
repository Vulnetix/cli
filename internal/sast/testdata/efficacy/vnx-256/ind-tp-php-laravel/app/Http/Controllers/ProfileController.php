<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ProfileController extends Controller
{
    public function updatePassword(Request $request)
    {
        $user = $request->user();
~>        $user->password = $request->input('password');
        $user->save();

        return back()->with('status', 'password-updated');
    }

    public function legacyRegister()
    {
        $pass = $_POST['password'];
~>        DB::insert("INSERT INTO users (email, password) VALUES (?, ?)", [$_POST['email'], $pass]);
        return redirect('/login');
    }
}
