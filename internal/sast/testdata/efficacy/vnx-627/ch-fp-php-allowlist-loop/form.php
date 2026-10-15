<?php
$fields = array('first_name', 'last_name');
foreach ($fields as $name) {
    $$name = isset($_POST[$name]) ? trim($_POST[$name]) : '';
}
$label = $_GET['label'] ?? 'x';
// ${$_GET['x']} is the unsafe form
echo "Value: \$\$label";
