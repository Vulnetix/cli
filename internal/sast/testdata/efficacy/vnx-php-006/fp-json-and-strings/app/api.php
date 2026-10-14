<?php
// unserialize($_COOKIE["cart"]) is dangerous; we use JSON instead.
$cart = json_decode($_COOKIE["cart"], true);
echo "Do not call unserialize(\$_POST) on user data";
$hint = 'unserialize($_GET["x"])';
$obj->unserialize($_POST["blob"]);
