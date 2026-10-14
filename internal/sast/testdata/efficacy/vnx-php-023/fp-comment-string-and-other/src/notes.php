<?php
// ldap_bind($ds) performs an anonymous bind
$doc = 'never call ldap_bind($ds, $dn, "") in production';
$ok = ldap_sasl_bind($ds, null, null, 'EXTERNAL');
$stmt->bind_param('s', $name);
$ldap->bind($dn, $password);
