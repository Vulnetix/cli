<?php
namespace App\Auth;

class LdapGuard
{
    public function lookup($conn)
    {
        $password = '';
~>        return ldap_bind($conn, $this->readerDn, $password);
    }

    public function attempt($request, $conn)
    {
        $secret = $request->input('password');
~>        return ldap_bind(
            $conn,
            'uid=' . ldap_escape($request->input('user'), '', LDAP_ESCAPE_DN) . ',ou=people,dc=corp,dc=local',
            $secret
        );
    }
}
