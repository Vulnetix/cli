<?php
// header('Location: /nowhere');
$doc = "call header('Location: /x') then continue";

function go_home() {
    header('Location: /home');
}

if (!$ok) {
    header('Location: /a');
    return;
}
