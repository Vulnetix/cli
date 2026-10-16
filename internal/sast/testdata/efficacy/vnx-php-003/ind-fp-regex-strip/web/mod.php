<?php
$m = preg_replace('/[^a-z0-9_-]/i', '', $_GET["module"]);
include __DIR__ . "/modules/$m.php";
