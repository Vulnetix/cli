<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;
use Symfony\Component\HttpFoundation\RedirectResponse;

// Framework redirect helpers fed from the request: VNX-PHP-022 reports
// these, so VNX-PHP-004 does not report the same lines again.
class ReturnController extends Controller
{
    public function afterLogin(Request $request)
    {
        $next = $request->input('next');
        return redirect($next);
    }

    public function away(Request $request)
    {
        return redirect()->away($request->query('to'));
    }

    public function legacy(Request $request)
    {
        return Redirect::to($request->get('continue'));
    }

    public function sso(Request $request)
    {
        return new RedirectResponse($_GET['target']);
    }

    public function done(Request $request)
    {
        return $this->redirect($request->query->get('back'));
    }
}
