<?php
require __DIR__ . '/config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /contact.html');
    exit;
}

$name    = trim($_POST['name'] ?? '');
$subject = $_POST['subject'] ?? 'Website enquiry';
$message = $_POST['message'] ?? '';

~>$headers  = "From: " . $name . " <noreply@example.org>\r\n";
~>$headers .= "Reply-To: " . $_POST['email'] . "\r\n";
$headers .= "MIME-Version: 1.0\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

~>$sent = mail(SUPPORT_ADDRESS, $subject, $message, $headers);

header('Location: /thanks.html');
