<?php
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

class LoginController extends AbstractController
{
    public function done(Request $request): RedirectResponse
    {
        if ($request->query->has('next')) {
~>            return $this->redirect($request->query->get('next'));
        }
~>        return new RedirectResponse($request->get('return_to'));
    }
}
