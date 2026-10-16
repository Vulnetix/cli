<?php
require __DIR__ . '/../bootstrap.php';

$path = __DIR__ . '/../storage/uploads/contacts.csv';
$lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
array_shift($lines);

$stmt = $pdo->prepare('INSERT INTO contacts (name, email, phone) VALUES (?, ?, ?)');
foreach ($lines as $line) {
~>    $fields = explode(",", $line);
    $stmt->execute([$fields[0], $fields[1], $fields[2]]);
}
echo count($lines) . " contacts imported\n";
