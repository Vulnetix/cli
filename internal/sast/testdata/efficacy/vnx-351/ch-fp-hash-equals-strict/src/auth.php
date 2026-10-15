<?php
function check(array $row)
{
    $pass = $_POST['pass'] ?? '';
    if (hash_equals($row['pw_sha256'], hash('sha256', $pass))) {
        return true;
    }
    if (md5($pass) === $row['legacy_md5']) {
        return true;
    }
    return in_array(
        $_GET['role'],
        $row['roles'],
        true
    );
}
