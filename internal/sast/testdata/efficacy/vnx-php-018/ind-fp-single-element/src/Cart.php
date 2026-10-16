<?php
session_start();
var_dump($_SESSION['cart_count']);
print_r($_SERVER['REQUEST_METHOD']);
$data = ['a' => 1];
print_r($data);
