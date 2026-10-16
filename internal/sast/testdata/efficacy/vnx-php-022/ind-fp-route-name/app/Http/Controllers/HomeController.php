<?php

namespace App\Http\Controllers;

class HomeController extends Controller
{
    public function go()
    {
        return redirect()->route('home');
    }
    public function other()
    {
        return redirect('/dashboard');
    }
}
