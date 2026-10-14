<?php
function lookup($ds, $base)
{
    $uid = $_GET['uid'];
    if (!preg_match('/^[a-z0-9._-]{1,32}$/', $uid)) {
        http_response_code(400);
        exit;
    }
    $sr = ldap_search($ds, $base, "(uid=$uid)");
    $emp = $_GET['employee'];
    if (!ctype_digit($emp)) {
        exit;
    }
    return ldap_list($ds, $base, '(employeeNumber=' . $emp . ')');
}
