<?php
namespace Corp\Directory;

function lookup($ds)
{
    $uid = $_GET['uid'];
~>    $res = \ldap_search($ds, 'ou=people,dc=corp,dc=example', "(uid=$uid)", ['cn', 'mail']);
    return $res;
}
