<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AvatarController extends Controller
{
    public function store(Request $request)
    {
        $path = $request->file('avatar')->store('avatars');
        $request->file('avatar')->storeAs('avatars', $request->user()->id . '.jpg');
        $f = $request->file('cv');
        $f->move(storage_path('cv'), $f->hashName());
        return $path;
    }
}
