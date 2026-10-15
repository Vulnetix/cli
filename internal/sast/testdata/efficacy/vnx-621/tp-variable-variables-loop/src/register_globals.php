<?php
foreach ($_GET as $key => $value) {
~>    $$key = $value;
}

foreach ($_POST as $k => $v) {
    $k = trim($k);
~>    ${$k} = $v;
}

~>import_request_variables('gp', '');
