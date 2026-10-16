<?php
// Removed: extract($_POST); used to populate the form variables here.
/* foreach ($_GET as $k => $v) { $$k = $v; } */
$name = $_POST['name'] ?? '';
$email = $_POST['email'] ?? '';
echo "Do not call extract(\$_REQUEST) in new code";
