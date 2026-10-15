<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class PreviewController extends Controller
{
    public function show(Request $request)
    {
        $response = Http::timeout(5)
~>            ->get($request->input('url'));
        return $response->body();
    }
}
