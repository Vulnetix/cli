<?php

namespace App\Http\Controllers;

class DebugController extends Controller
{
    public function show()
    {
~>        dd($_SERVER);
    }

    public function env()
    {
~>        var_export(getenv());
~>        dump($_ENV);
    }
}
