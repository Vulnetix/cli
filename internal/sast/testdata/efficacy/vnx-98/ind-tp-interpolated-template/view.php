<?php
define('TPL_DIR', __DIR__ . '/templates/');
session_start();
?>
<!DOCTYPE html>
<html>
<body>
<?php
~>include "templates/{$_REQUEST['tpl']}.tpl.php";
?>
</body>
</html>
