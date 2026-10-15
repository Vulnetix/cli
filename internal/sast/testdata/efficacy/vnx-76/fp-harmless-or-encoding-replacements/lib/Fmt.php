<?php
function fmt($x) {
    $x = str_replace(' ', '', $x);
    return htmlspecialchars($x, ENT_QUOTES, 'UTF-8');
}
