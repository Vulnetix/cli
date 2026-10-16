<?php
function render_vars($tpl, $vars) {
    return preg_replace_callback('/\{\$(\w+)\}/', fn ($m) => htmlspecialchars($vars[$m[1]] ?? ''), $tpl);
}
$a = preg_replace('/\s+/u', ' ', $_POST['comment']);
$b = preg_replace('/^abc$/im', 'x', $subject);
$c = preg_replace('/a b/x', 'y', $_GET['q']);
// $d = preg_replace('/x/e', 'phpinfo()', $s);
$msg = "preg_replace('/x/e', ...) is removed in PHP 7";
