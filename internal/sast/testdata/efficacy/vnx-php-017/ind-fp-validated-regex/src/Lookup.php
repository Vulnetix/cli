<?php
$name = $_GET['name'] ?? '';
if (!preg_match('/^[A-Za-z0-9._-]{1,32}$/', $name)) {
    http_response_code(400);
    exit;
}
$filter = "(&(objectClass=person)(uid=$name))";
$r = ldap_search($conn, 'dc=example,dc=com', $filter);
