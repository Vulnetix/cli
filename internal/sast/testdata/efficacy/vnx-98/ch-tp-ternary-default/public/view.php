<?php
$view = isset($_POST['view']) ? $_POST['view'] : 'dashboard';

?>
<html>
<body>
~><?php include_once("views/" . $view); ?>
</body>
</html>
