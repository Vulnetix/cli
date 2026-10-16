<?php
$file = $_GET['page'];
$file = str_replace(array("http://", "https://"), "", $file);
$file = str_replace( array( "../", "..\\" ), "", $file );

$target = $_REQUEST['ip'];
~>$target = str_replace(array('&&', ';'), '', $target);

$name = str_ireplace("<script>", "", $_POST['name']);
$msg = preg_replace('/<script>/i', '', $_POST['msg']);
