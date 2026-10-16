<?php
session_start();
$sig = $_POST['signature'];
~>if ($sig == hash_hmac('sha256', $_POST['payload'], WEBHOOK_SECRET)) {
    process($_POST['payload']);
}

~>if ($_SESSION['csrf_token'] != $_POST['csrf']) {
    http_response_code(403);
    exit;
}
