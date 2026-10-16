<?php
setcookie('is_admin', $user->isAdmin ? '1' : '0', time() + 3600);
if (!isset($_COOKIE['consent'])) {
    echo "banner";
}
