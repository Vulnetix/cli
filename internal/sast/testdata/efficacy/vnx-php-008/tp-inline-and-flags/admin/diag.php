<html><body>
~><?php phpinfo(INFO_GENERAL | INFO_MODULES); ?>
<?php
if ($_GET["show"] === "env") {
~>    \phpinfo( INFO_ENVIRONMENT );
}
