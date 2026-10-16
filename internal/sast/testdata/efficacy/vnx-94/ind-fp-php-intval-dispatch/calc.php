<?php
$n = intval($_GET['n'] ?? 0);
eval('$r = ' . intval($_GET['n']) . ' * 2;');

$ops = [
    'add' => fn($a, $b) => $a + $b,
    'mul' => fn($a, $b) => $a * $b,
];
$op = $_POST['op'] ?? 'add';
if (!array_key_exists($op, $ops)) {
    http_response_code(400);
    exit;
}
echo $ops[$op]($n, $r);
