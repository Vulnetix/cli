<?php
~>include($_GET['page']);
~>echo file_get_contents($_GET['file']);

$log = $_POST['log'];
~>unlink("/var/log/app/" . $log);

$page = $_REQUEST['p'];
~>include $page;
