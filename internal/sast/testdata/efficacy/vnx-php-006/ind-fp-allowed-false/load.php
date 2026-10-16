<?php
$a = unserialize($_COOKIE["cart"], ["allowed_classes" => false]);
$opts = ["allowed_classes" => false];
$b = unserialize($_POST["x"], $opts);
$c = unserialize($_GET["y"], ["allowed_classes" => [Cart::class]]);
