<?php
namespace App;

class Bootstrap
{
    public function run()
    {
        if (isset($_GET['debug'])) {
~>            var_dump(
                $_ENV
            );
~>            die(var_export($GLOBALS, true));
        }
    }
}
