<?php

namespace App\Http\Controllers;

class DebugController extends Controller
{
    public function index()
    {
~>        dd($_SERVER);
    }
}
