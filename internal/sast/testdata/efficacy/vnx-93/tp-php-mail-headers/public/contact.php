<?php
$email = $_POST['email'];
~>$headers = "From: " . $email . "\r\n";
$headers .= "Content-Type: text/plain\r\n";
~>mail("support@example.com", $_POST['subject'], $_POST['message'], $headers);
~>mail($_GET['to'], "Welcome", "Thanks for signing up");
