<?php
~>foreach ($_GET as $k => $v) $$k = $v;
foreach (array_keys($_REQUEST) as $field) {
~>    $$field = $_REQUEST[$field];
}
foreach ($_POST as $name => $value) {
~>    $GLOBALS[$name] = $value;
}
