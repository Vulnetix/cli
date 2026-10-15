<?php
// include($_GET['page']);  -- removed: LFI
/* require $_POST['lib']; */
$warning = "never include(\$_GET['page'])";
echo $warning;
$included = $_GET['included'];
echo $included;
