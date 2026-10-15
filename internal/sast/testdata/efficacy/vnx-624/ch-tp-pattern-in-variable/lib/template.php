<?php
function render_template($tpl, $vars)
{
~>    $pattern = '/\{\$(\w+)\}/e';
    return preg_replace($pattern, '$vars["\\1"]', $tpl);
}
