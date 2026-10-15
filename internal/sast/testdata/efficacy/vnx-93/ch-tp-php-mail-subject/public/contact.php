<?php
$to = 'support@example.org';
$message = wordwrap($_POST['message'], 70);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
~>    $sent = mail(
        $to,
        $_POST['subject'],
        $message
    );
    echo $sent ? 'Thanks' : 'Failed';
}
