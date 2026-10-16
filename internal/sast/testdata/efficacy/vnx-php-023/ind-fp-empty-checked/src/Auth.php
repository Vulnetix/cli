<?php
function authenticate($ds, string $dn, string $pass): bool
{
    if (empty($pass)) {
        return false;
    }
    return @ldap_bind($ds, $dn, $pass);
}
