<?php
// extract($_POST) is dangerous; do not call it here.
$sql = "SELECT extract(year from created_at) FROM orders";
$zip->extract($_POST['dest']);
$parts = Archive::extract($_GET['file']);
$value = json_extract($payload, '$.name');
$msg = 'never extract($_REQUEST) in production';
$name = $$fieldName;
$label = ${$prefix . 'label'};
