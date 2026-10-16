<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;

class PrefController extends Controller
{
    public function store(Request $request)
    {
        $key = $request->input('key');
        $value = $request->input('value');
~>        Session::put($key, $value);
        return back();
    }
}
