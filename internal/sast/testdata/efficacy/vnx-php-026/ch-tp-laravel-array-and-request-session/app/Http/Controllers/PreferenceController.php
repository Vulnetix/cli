<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class PreferenceController extends Controller
{
    public function store(Request $request)
    {
        $name = $request->input('preference');
        $value = $request->input('value');
~>        $request->session()->put($name, $value);

        return back();
    }

    public function remember(Request $request)
    {
        $field = $request->get('field');
~>        session()->put($field, true);
        return response()->noContent();
    }
}
