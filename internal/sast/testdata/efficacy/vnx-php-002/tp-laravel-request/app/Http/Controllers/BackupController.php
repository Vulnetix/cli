<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class BackupController extends Controller
{
    public function run(Request $request)
    {
        $db = $request->input("database");
        $target = "/var/backups/" . $db . ".sql";
~>        exec("mysqldump {$db} > {$target}");
        return response()->json(["ok" => true]);
    }

    public function archive(Request $request)
    {
~>        shell_exec("tar czf /tmp/out.tgz " . $request->query("path"));
    }
}
