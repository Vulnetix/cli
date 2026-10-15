<?php
$email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
$headers = "From: " . $email . "\r\n";
$subject = str_replace(array("\r", "\n"), '', $_POST['subject']);
$headers .= "X-Subject: " . $subject . "\r\n";
mail("support@example.com", $subject, $_POST['message'], $headers);
$name = $_POST['name'];
if (!preg_match('/^[A-Za-z ]+$/', $name)) {
    exit;
}
$h = "X-Name: " . $name . "\r\n";
mail("support@example.com", "Contact", $_POST['message']);
// mail($_GET['to'], "x", "y");
