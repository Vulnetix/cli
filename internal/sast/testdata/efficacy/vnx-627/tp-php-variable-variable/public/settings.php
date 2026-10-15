<?php
$is_admin = false;
$name = $_GET['var'];
~>$$name = $_GET['value'];

~>echo ${$_POST['show']};

$key = $_REQUEST['k'];
~>${$key} = 'x';
