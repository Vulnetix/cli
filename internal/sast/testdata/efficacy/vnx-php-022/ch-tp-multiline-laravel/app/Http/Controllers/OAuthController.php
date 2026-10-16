<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class OAuthController extends Controller
{
    public function callback(Request $request)
    {
~>        return redirect()->away(
            $request->input('callback')
        );
    }

    public function back(Request $request)
    {
        $return = $request->input('return', '/');
        $target = urldecode($return);
        header('Location: ' . $target);
        exit;
    }
}
