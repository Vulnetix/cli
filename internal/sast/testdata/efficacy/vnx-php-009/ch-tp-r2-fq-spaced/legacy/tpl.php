<?php
namespace Legacy;

function render($tpl, $vars) {
~>    return \preg_replace ( "/\{(\w+)\}/e" , '$vars["\\1"]', $tpl );
}

function filt($in) {
~>    return preg_filter(['/a/e', '/b/'], ['x', 'y'], $in);
}
