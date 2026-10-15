<?php
$allowed = ['strtoupper', 'strtolower', 'ucfirst'];
$fn = $_GET['fn'] ?? 'strtolower';
if (!in_array($fn, $allowed, true)) {
    http_response_code(400);
    exit;
}
$result = call_user_func($fn, $_GET['text']);

$n = (int) $_POST['n'];
eval('$square = ' . $n . ' * ' . $n . ';');
echo $result, $square;
