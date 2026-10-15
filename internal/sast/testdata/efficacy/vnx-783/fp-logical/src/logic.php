<?php
function logic($a, $b) {
    if (!$a == false) {
        return 1;
    }
    if ($a == $b && $b != 0) {
        return 2;
    }
    if (($row = fetch($a)) !== null) {
        return 3;
    }
    return "Role: " . ($a ? "admin" : "user");
}
