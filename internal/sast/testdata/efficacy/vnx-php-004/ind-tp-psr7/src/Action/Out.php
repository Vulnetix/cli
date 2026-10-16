<?php
namespace App\Action;

class Out
{
    public function __invoke($request, $response)
    {
~>        return $response->withHeader("Location", $_GET["r"]);
    }
}
