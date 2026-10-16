<?php
require_once __DIR__ . '/../bootstrap.php';

function sanitize_entry(string $text): string
{
~>    $text = preg_replace('#<iframe[^>]*>.*?</iframe>#s', '', $text);
~>    $text = str_replace("javascript:", "", $text);
    return trim($text);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = sanitize_entry($_POST['name'] ?? '');
    $message = sanitize_entry($_POST['message'] ?? '');
~>    if (strpos($message, '<script') !== false) {
        http_response_code(400);
        exit('rejected');
    }
    $stmt = $pdo->prepare('INSERT INTO guestbook (name, message) VALUES (?, ?)');
    $stmt->execute([$name, $message]);
}
