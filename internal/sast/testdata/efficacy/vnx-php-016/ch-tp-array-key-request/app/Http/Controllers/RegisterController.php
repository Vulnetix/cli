<?php
namespace App\Http\Controllers;

class RegisterController extends Controller
{
    public function store($request)
    {
        return User::create([
            'email' => $request->input('email'),
~>            'password' => md5($request->input('password')),
        ]);
    }
}
