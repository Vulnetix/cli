<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserController extends Controller
{
    public function find(Request $request)
    {
~>        return DB::select("SELECT * FROM users WHERE email = '" . $request->input('email') . "'");
    }

    public function rename(Request $request)
    {
~>        DB::statement("UPDATE users SET name = '" . $request->get('name') . "' WHERE id = 1");
    }
}
