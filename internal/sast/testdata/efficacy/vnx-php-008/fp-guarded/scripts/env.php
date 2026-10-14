<?php
if (php_sapi_name() === "cli") {
    phpinfo();
}

if (app()->isLocal()) {
    phpinfo(INFO_CONFIGURATION);
}
