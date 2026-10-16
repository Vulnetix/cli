<?php
$user = ldap_escape($_POST['username'], '', LDAP_ESCAPE_FILTER);
$sr = ldap_search($ds, 'dc=example,dc=com', "(uid=$user)", ['dn', 'mail']);
$count = ldap_count_entries($ds, $sr);
