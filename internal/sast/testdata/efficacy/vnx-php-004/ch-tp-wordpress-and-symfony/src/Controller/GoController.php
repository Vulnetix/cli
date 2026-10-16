<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

class GoController
{
    public function go(Request $request): RedirectResponse
    {
        return new RedirectResponse($request->query->get('target'));
    }
}
