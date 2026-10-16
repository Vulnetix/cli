<?php
// never call system($_GET["cmd"]) or eval($_POST["x"])
/* shell_exec("ping " . $_GET["host"]); */
$warning = 'Do not use exec($_REQUEST["c"]) in handlers';
echo $warning;
