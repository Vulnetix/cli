<?php
// Never do: ldap_search($ds, $dn, "(uid=" . $_GET['u'] . ")");
/*
 * ldap_list($ds, $dn, $_POST['filter']) is an injection.
 */
echo 'Example: ldap_search($ds, $dn, "(uid=" . $_GET["u"] . ")")';
$doc = "ldap_read is unsafe with \$_REQUEST input";
