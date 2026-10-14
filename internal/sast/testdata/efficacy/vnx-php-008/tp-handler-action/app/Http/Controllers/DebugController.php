<?php

namespace App\Http\Controllers;

class DebugController extends Controller
{
    public function info()
    {
        ob_start();
~>        phpinfo();
        return response(ob_get_clean());
    }
}
