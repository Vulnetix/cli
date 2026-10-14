<?php

namespace App\Http\Controllers;

class AvatarController extends Controller
{
    public function store($request)
    {
        $request->validate(['avatar' => 'required|image|mimes:jpg,png|max:2048']);
        $path = $request->file('avatar')->store('avatars');
        $file = $request->file('doc');
        $file->move(storage_path('docs'), $file->hashName());
        $original = $file->getClientOriginalName();
        return $path . $original;
    }
}
