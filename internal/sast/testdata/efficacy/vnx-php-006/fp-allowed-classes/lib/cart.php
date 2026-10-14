<?php
$cart = unserialize($_COOKIE["cart"], ["allowed_classes" => false]);
$items = unserialize($_POST["items"], ['allowed_classes' => [CartItem::class]]);
$data = unserialize(
    $_GET["d"],
    array("allowed_classes" => false)
);
