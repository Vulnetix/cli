<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ThemeController extends Controller
{
    public function show(Request $request)
    {
        $theme = $request->input('theme');
~>        include resource_path('themes/' . $theme . '/layout.php');
        return view('theme');
    }
}
