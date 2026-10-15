<?php
namespace App;

use Symfony\Component\Ldap\Ldap;

class Auth
{
    public function external($link)
    {
        return ldap_sasl_bind($link, null, null, 'EXTERNAL');
    }

    public function symfony(Ldap $ldap, string $dn, string $password)
    {
        $ldap->bind($dn, $password);
    }

    public function service($link, array $cfg)
    {
        return ldap_bind($link, $cfg['bind_dn'], $cfg['bind_password']);
    }
}
