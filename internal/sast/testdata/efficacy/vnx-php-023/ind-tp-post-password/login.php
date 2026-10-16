<?php
$link = ldap_connect(LDAP_URI);
~>if (ldap_bind($link, 'uid=' . $_POST['username'] . ',ou=people,dc=example,dc=com', $_POST['password'])) {
    $_SESSION['user'] = $_POST['username'];
}
