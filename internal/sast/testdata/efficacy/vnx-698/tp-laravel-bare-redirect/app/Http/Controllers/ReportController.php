<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ReportController extends Controller
{
    public function destroy(Request $request, $id)
    {
        if (! $request->user()->isAdmin()) {
~>            redirect('/home');
        }
        Report::findOrFail($id)->delete();
        return back();
    }

    public function archive(Request $request, $id)
    {
        if (! $request->user()->owns($id)) {
~>            redirect()->route('reports.index');
        }
        Report::findOrFail($id)->archive();
        return back();
    }
}
