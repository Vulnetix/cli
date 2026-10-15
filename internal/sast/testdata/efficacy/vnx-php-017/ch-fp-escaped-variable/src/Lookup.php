<?php
function find_user($ds, $base)
{
    $user = ldap_escape($_POST['user'], '', LDAP_ESCAPE_FILTER);
    return ldap_search($ds, $base, "(uid=$user)");
}
