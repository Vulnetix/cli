<?php
/**
 * Never write: ldap_search($ds, $base, "(uid=" . $_GET['u'] . ")");
 */
// $sr = ldap_search($ds, $base, '(uid=' . $_POST['u'] . ')');
$help = 'ldap_search($ds, $base, $_GET["filter"]) is unsafe';
echo $help;
