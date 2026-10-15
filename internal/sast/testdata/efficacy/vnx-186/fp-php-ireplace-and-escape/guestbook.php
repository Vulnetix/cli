<?php
$name = str_ireplace('<script>', '', $_POST['name']);
$msg = preg_replace('/<script(.*?)>/i', '', $_POST['msg']);
echo htmlspecialchars($msg, ENT_QUOTES, 'UTF-8');
