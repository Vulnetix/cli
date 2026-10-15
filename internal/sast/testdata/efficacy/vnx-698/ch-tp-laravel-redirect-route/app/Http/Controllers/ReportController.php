<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ReportController extends Controller
{
    public function show(Request $request, $id)
    {
        if (! $request->user()->can('view-reports')) {
~>            redirect()->route('home');
        }
        return view('reports.show', ['id' => $id]);
    }
}
