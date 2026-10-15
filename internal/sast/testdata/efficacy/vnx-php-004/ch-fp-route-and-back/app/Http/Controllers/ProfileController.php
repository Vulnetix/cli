<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function update(Request $request)
    {
        if ($request->input('cancel')) {
            return redirect()->route('profile.show', ['id' => $request->input('id')]);
        }
        return back()->with('next', $_GET['next'] ?? null)->withInput($request->all());
    }
}
