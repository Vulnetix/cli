<?php
namespace App\Directory;

class PeopleFinder
{
    public function find($conn)
    {
        $name = $_GET['name'];
        $filter = "(&(objectClass=inetOrgPerson)(cn=$name))";
~>        $result = ldap_list($conn, 'ou=people,dc=corp,dc=local', $filter, ['cn', 'mail']);
        return ldap_get_entries($conn, $result);
    }
}
