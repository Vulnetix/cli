<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class StatusController extends Controller
{
    const STATUSES = [1, 2, 3];

    public function update(Request $request)
    {
~>        abort_unless(in_array($request->input('status'), self::STATUSES), 422);
    }
}
