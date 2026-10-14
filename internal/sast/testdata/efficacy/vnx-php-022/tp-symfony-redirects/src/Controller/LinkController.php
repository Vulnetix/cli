<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

class LinkController extends AbstractController
{
    public function out(Request $request)
    {
~>        return $this->redirect($request->query->get('target'));
    }

    public function jump(Request $request)
    {
        $dest = $request->get('to');
~>        return new RedirectResponse(
            $dest
        );
    }
}
