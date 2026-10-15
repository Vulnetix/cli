<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ImportController extends Controller
{
    public function store(Request $request)
    {
~>        $payload = unserialize($request->getContent());
        $body = $request->getContent();
~>        $items = unserialize(gzuncompress($body));
        return response()->json(['count' => count($items)]);
    }
}
