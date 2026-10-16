<?php
function render_vars($tpl, $vars) {
~>    return preg_replace('/\{\$(\w+)\}/e', '$vars["\\1"]', $tpl);
}
