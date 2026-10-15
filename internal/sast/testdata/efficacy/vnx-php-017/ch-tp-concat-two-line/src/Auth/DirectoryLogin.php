<?php
namespace App\Auth;

class DirectoryLogin
{
    public function find($conn, string $baseDn)
    {
        $filter = "(&(objectClass=user)(sAMAccountName=" . $_POST['username'] . "))";
~>        $sr = ldap_search($conn, $baseDn, $filter);
        return ldap_get_entries($conn, $sr);
    }
}
