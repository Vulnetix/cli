<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ArchiveController extends Controller
{
    public function make(Request $request)
    {
~>        $result = shell_exec("tar czf /tmp/out.tgz " . $request->query("path"));
        return response()->json(["ok" => $result !== null]);
    }
}
