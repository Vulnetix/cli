<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class PlanController extends Controller
{
    public function change(Request $request)
    {
        $data = $request->json()->all();
~>        if (in_array($data['plan'], config('billing.plans'))) {
            $request->user()->update(['plan' => $data['plan']]);
        }
    }
}
