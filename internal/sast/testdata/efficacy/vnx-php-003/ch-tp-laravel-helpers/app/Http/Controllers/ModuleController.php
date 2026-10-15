<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ModuleController extends Controller
{
    public function boot(Request $request)
    {
~>        include base_path('modules/' . $request->input('module') . '/boot.php');
~>        return include resource_path('views/' . $request->query('view'));
    }
}
