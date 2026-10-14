<?php
~>echo '<pre>' . print_r($_SERVER, true) . '</pre>';
~>echo "<pre>", var_export($_SESSION, true), "</pre>";
?>
<div class="env">
~><?= print_r($_ENV, true) ?>
</div>
