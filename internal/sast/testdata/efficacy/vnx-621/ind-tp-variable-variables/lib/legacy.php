<?php
function register_globals_emulation() {
    foreach ($_GET as $key => $value) {
~>        $$key = $value;
    }
}
