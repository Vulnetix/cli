<?php
function lookup_mail($ds)
{
    $email = trim($_POST['email']);
    $filter = sprintf('(mail=%s)', $email);
~>    $sr = ldap_list($ds, 'ou=staff,dc=example,dc=org', $filter, array('uid'));
    return ldap_get_entries($ds, $sr);
}

function read_entry($ds)
{
~>    $sr = ldap_read($ds, 'uid=' . $_COOKIE['uid'] . ',ou=staff,dc=example,dc=org', '(objectClass=*)');
    return ldap_get_entries($ds, $sr);
}
