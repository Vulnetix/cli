<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class HomeController extends Controller
{
    public function index(Request $request)
    {
        if ($request->input('back')) {
            return redirect()->back();
        }
        return redirect()->route('home', ['tab' => $request->input('tab')]);
    }

    public function show()
    {
        return redirect('/profile');
    }

    public function symfony()
    {
        return $this->redirect($this->generateUrl('app_home'));
    }
}
