<?php
$cc = $_POST['cc'];
~>setcookie("cc_number", $cc, time() + 3600, "/");
header("Location: /confirm.php");
