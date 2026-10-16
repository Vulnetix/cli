<?php
// Calling ldap_bind($conn) is anonymous; we never do that.
// ldap_bind($conn, $dn, '') is also wrong.
$ok = ldap_bind($conn, $config['dn'], $config['secret']);
