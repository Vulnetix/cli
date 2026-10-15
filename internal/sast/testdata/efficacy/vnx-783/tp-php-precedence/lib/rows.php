<?php
const PERM_WRITE = 2;

function rows($res, $perms, $isAdmin)
{
    $out = [];
~>    while ($row = mysqli_fetch_assoc($res) !== null) {
        $out[] = $row;
    }
~>    if ($perms & PERM_WRITE == 0) {
        return [];
    }
~>    $label = "Role: " . $isAdmin ? "admin" : "user";
    return $out;
}
