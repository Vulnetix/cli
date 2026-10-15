<?php
if (PHP_SAPI !== 'cli') {
~>    phpinfo();
} else {
    echo php_ini_loaded_file(), PHP_EOL;
}
