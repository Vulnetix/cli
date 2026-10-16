<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class TeamController extends Controller
{
    public function switch(Request $request)
    {
        $teamIds = $request->user()->teams()->pluck('id')->all();
~>        $pos = array_search($request->input('team_id'), $teamIds);
        if ($pos === false) {
            abort(403);
        }
        return redirect('/teams/' . $teamIds[$pos]);
    }
}
