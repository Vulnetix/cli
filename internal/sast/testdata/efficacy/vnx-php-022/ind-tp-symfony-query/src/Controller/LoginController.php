<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;

class LoginController extends AbstractController
{
    public function after(Request $request)
    {
~>        return $this->redirect($request->query->get('target'));
    }
}
