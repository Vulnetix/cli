<?php
$blocked = array('php', 'phtml', 'phar');
$ext = pathinfo($_FILES['doc']['name'], PATHINFO_EXTENSION);
~>if (in_array($ext, $blocked)) {
    die('not allowed');
}
move_uploaded_file($_FILES['doc']['tmp_name'], 'files/' . basename($_FILES['doc']['name']));
