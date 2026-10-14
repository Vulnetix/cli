<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AttachmentController extends Controller
{
    public function store(Request $request)
    {
        $file = $request->file('attachment');
~>        $file->move(public_path('uploads'), $file->getClientOriginalName());
~>        $path = $request->file('photo')->storeAs('public/photos', $request->file('photo')->getClientOriginalName());
        return back();
    }
}
