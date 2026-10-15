<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class DocController extends Controller
{
    public function store(Request $request)
    {
        $file = $request->file('doc');
~>        $file->storeAs('public/docs', $file->getClientOriginalName());
    }
}
