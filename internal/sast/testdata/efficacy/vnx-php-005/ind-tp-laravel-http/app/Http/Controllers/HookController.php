<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class HookController extends Controller
{
    public function test(Request $request)
    {
        $hook = $request->input("webhook_url");
~>        Http::timeout(5)->post($hook, ["ping" => true]);
        return back();
    }
}
