<?php
$ds = ldap_connect(getenv('LDAP_HOST'));
$sr = ldap_search($ds, 'dc=corp,dc=local', '(objectClass=user)');
$filter = getenv('LDAP_GROUP_FILTER');
$groups = ldap_list($ds, 'ou=groups,dc=corp,dc=local', $filter);
$page = (int) $_GET['page'];
$entry = ldap_read($ds, 'cn=admins,ou=groups,dc=corp,dc=local', '(objectClass=*)');
echo "page $page";
