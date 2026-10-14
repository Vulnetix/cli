<?php
function find_user($ds, $base)
{
    $user = ldap_escape($_POST['username'], '', LDAP_ESCAPE_FILTER);
    $sr = ldap_search($ds, $base, "(uid=$user)");
    $mail = $_POST['mail'];
    $sr2 = ldap_search($ds, $base, '(mail=' . ldap_escape($mail, '', LDAP_ESCAPE_FILTER) . ')');
    $raw = $_GET['cn'];
    $safe = ldap_escape($raw, '', LDAP_ESCAPE_FILTER);
    $filter = "(cn=$safe)";
    return ldap_search($ds, $base, $filter);
}
