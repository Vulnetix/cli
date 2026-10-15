<?php
class Groups
{
    public function members($ds)
    {
        $group = $_GET['group'];
        $this->audit($group);
        $group = 'engineering';
        $filter = sprintf('(&(objectClass=posixGroup)(cn=%s))', $group);
        $a = ldap_search($ds, $this->config['base_dn'], $filter);
        $b = ldap_list($ds, $this->config['base_dn'], $this->config['group_filter']);
        return [$a, $b];
    }
}
