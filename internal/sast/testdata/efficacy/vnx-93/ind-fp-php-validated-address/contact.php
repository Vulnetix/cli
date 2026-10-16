<?php
$email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
if ($email === false) {
    http_response_code(422);
    exit('Please enter a valid email address.');
}

$subject = str_replace(array("\r", "\n"), '', $_POST['subject'] ?? 'Enquiry');

$headers  = "From: Website <noreply@example.org>\r\n";
$headers .= "Reply-To: " . $email . "\r\n";

// The visitor's message only ever goes into the body.
mail("support@example.org", $subject, $_POST['message'] ?? '', $headers);
