<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class SkinController extends Controller
{
    public function show(Request $request)
    {
        $skin = $request->input('skin', 'default');
        ob_start();
~>        require base_path("skins/{$skin}/header.php");
        return response(ob_get_clean());
    }
}
