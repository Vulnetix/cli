<?php
session_start();
if (isset($_GET['debug'])) {
~>    var_dump($_SESSION);
~>    var_dump ($user, $_SERVER);
}
~>print_r($_ENV);
