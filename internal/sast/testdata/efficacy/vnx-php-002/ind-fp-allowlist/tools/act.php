<?php
$action = $_GET["action"];
if (!in_array($action, ["start", "stop", "status"], true)) {
    http_response_code(400);
    exit;
}
exec("/usr/sbin/service myapp " . $action, $out);
