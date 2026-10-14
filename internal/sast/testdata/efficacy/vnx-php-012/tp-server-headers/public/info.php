<?php

~>$page['body'] .= "Your user-agent is: <em>{$_SERVER['HTTP_USER_AGENT']}</em><br />";
?>
~><form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post">
<?php
$callback = $_GET['callback'];
~>echo $callback . "(" . json_encode($data) . ")";
