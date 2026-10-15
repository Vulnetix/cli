<?php
$handler = $_GET['callback'];
$data = load_rows();
~>$out = call_user_func($handler, $data);

$expr = $_POST['expr'];
~>eval("\$total = " . $expr . ";");

echo json_encode(['out' => $out, 'total' => $total]);
