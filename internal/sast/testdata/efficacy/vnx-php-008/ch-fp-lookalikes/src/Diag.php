<?php
if (function_exists('phpinfo')) {
    $disabled = in_array('phpinfo', explode(',', ini_get('disable_functions')), true);
}
$report->phpinfo();
Diagnostics::phpinfo();
$label = 'phpinfo()';
