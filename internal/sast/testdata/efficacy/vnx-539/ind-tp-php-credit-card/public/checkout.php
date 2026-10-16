<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $card = $_POST['card_number'];
~>    setcookie('credit_card', $card, time() + 86400 * 30, '/', '', true, true);
    header('Location: /checkout/confirm.php');
    exit;
}
