<?php
$email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
if ($email === false) {
    http_response_code(400);
    exit('invalid address');
}

$headers = "From: news@example.org\r\n";
$headers .= "Reply-To: " . $email . "\r\n";
mail('list@example.org', 'New subscriber', 'Subscriber: ' . $_POST['name'], $headers);
