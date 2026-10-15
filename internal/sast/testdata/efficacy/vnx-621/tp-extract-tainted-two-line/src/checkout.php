<?php
$input = $_POST;
$total = 0;
~>extract($input);
if ($discount_approved) {
    $total = $price * 0.5;
}

$cookie = json_decode($_COOKIE['prefs'], true);
~>extract($cookie);
