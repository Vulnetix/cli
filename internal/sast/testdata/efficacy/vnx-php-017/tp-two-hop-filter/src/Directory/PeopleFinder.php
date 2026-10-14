<?php
namespace App\Directory;

class PeopleFinder
{
    private $conn;

    public function find()
    {
        $name = $_GET['name'];
        $filter = "(&(objectClass=inetOrgPerson)(cn=$name))";
~>        $result = ldap_search($this->conn, 'dc=corp,dc=local', $filter, ['cn', 'mail']);
        return ldap_get_entries($this->conn, $result);
    }

    public function byDepartment()
    {
        $dept = $_REQUEST['dept'];
        $f = '(departmentNumber=';
        $f .= $dept . ')';
~>        return ldap_list($this->conn, 'ou=people,dc=corp,dc=local', $f);
    }
}
