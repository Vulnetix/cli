<?php
function render($tpl, array $vars) {
    return preg_replace_callback('/\{\$(\w+)\}/', function ($m) use ($vars) {
        return htmlspecialchars($vars[$m[1]] ?? '');
    }, $tpl);
}
$s = mb_ereg_replace('[^a-z]', '', $s);
$t = mb_ereg_replace('x', 'y', $t, 'msr');
