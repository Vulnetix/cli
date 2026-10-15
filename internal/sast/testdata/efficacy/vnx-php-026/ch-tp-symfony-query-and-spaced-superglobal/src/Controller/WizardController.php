<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class WizardController
{
    public function step(Request $request): Response
    {
        $session = $request->getSession();
        $step = $request->query->get('step');
~>        $session->set($step, $request->request->all());
        return new Response('ok');
    }
}

function legacy_step()
{
~>    $_SESSION[ $_REQUEST["step"] ] = $_REQUEST["data"];
~>    $_SESSION[trim($_GET['k'])] = 1;
}
