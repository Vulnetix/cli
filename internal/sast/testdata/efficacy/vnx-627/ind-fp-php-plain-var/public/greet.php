<?php
$fields = ['first_name', 'last_name'];
$name = $_GET['name'] ?? 'guest';
$safe = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
foreach ($fields as $field) {
    $$field = trim((string) ($_POST[$field] ?? ''));
}
echo "Hello, {$safe}";
// $$name = $_GET['value']; was removed in 2.3
