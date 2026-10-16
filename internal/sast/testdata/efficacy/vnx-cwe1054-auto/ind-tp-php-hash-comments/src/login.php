<?php
function login($u, $p) {
~>    # $hash = md5($p);
    # if ($hash === $row['pw']) {
    #     return true;
    # }
    return password_verify($p, $row['pw']);
}
