<?php
$user = $_POST['username'];
~>$result = ldap_search(
    $link,
    'ou=staff,dc=example,dc=com',
    "(&(uid=" . $user . ")(accountStatus=active))"
);
