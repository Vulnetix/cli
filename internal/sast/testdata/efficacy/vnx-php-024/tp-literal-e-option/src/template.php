<?php
function render($tpl, $vars)
{
~>    return mb_ereg_replace('\{(\w+)\}', '$vars["\\1"]', $tpl, 'e');
}

function render_ci($tpl)
{
~>    return mb_eregi_replace("%(\w+)%", "strtoupper('\\1')", $tpl, "msre");
}
