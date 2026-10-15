<?php
ob_start();
~>phpinfo();
$info = ob_get_clean();
echo '<div class="info">' . $info . '</div>';
