<?php
// Emulate register_globals for the old admin pages.
if (!ini_get('register_globals')) {
    foreach ($_REQUEST as $name => $value) {
~>        $GLOBALS[$name] = $value;
    }
~>    foreach ($_COOKIE as $ck => $cv) { $$ck = $cv; }
}
