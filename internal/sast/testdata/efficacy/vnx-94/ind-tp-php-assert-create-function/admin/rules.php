<?php
require_once __DIR__ . '/../bootstrap.php';

$check = $_GET['check'] ?? 'true';
~>assert($check);

$sortBody = $_POST['sort'] ?? 'return strcmp($a, $b);';
~>$comparator = create_function('$a, $b', $sortBody);
usort($items, $comparator);

~>$formatted = call_user_func($_REQUEST['formatter'], $items);
echo json_encode($formatted);
