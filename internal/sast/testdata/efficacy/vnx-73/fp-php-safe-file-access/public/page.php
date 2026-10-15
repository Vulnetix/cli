<?php
$allowed = ['home', 'about'];
$page = $_GET['page'];
if (!in_array($page, $allowed, true)) {
    http_response_code(404);
    exit;
}
include "pages/" . $page . ".php";
file_put_contents('/var/log/app.log', $_POST['msg'], FILE_APPEND);
echo file_get_contents('pages/' . basename($_GET['doc']));
