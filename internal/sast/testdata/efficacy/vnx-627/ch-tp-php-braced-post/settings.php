<?php
$is_admin = false;
$theme = 'light';

~>${$_POST['setting']} = $_POST['value'];

$key = $_GET['show'];
~>echo htmlspecialchars($$key);
