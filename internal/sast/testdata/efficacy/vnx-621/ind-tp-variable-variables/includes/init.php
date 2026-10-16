<?php
// Emulate register_globals for old templates.
foreach ($_REQUEST as $name => $value) {
~>    $$name = $value;
}

if (function_exists('import_request_variables')) {
~>    import_request_variables('gp', 'rv_');
}
