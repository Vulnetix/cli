<?php
function connect_reader($host)
{
    $conn = ldap_connect($host);
~>    ldap_bind($conn, 'cn=reader,dc=corp,dc=local', '');
~>    ldap_bind($conn, "cn=reader,dc=corp,dc=local", "");
~>    ldap_bind($conn, 'cn=reader,dc=corp,dc=local', NULL);
~>    ldap_bind($conn, 'cn=reader,dc=corp,dc=local');
~>    ldap_bind_ext($conn, 'cn=reader,dc=corp,dc=local', null);
    return $conn;
}
