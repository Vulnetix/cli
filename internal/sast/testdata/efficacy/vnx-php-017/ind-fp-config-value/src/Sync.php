<?php
$filter = sprintf('(&(objectClass=user)(memberOf=%s))', getenv('SYNC_GROUP_DN'));
$r = ldap_search($conn, getenv('LDAP_BASE'), $filter);
