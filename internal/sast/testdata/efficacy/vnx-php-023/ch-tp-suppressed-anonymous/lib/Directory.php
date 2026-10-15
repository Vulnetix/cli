<?php
namespace Corp\Ldap;

class Directory
{
    private $conn;

    public function connect(string $uri): bool
    {
        $this->conn = ldap_connect($uri);
        ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, 3);
~>        return @ldap_bind($this->conn);
    }

    public function connectNull(string $uri): bool
    {
        $c = \ldap_connect($uri);
~>        return \ldap_bind($c, null, null);
    }
}
