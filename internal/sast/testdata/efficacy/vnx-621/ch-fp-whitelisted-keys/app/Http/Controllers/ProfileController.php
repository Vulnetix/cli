<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function update(Request $request)
    {
        extract($request->only(['name', 'email']));
        extract(array_intersect_key($_POST, array_flip(['title', 'body'])));
        $data = $request->validated();
        extract($data);
        return view('profile', compact('name', 'email'));
    }
}
