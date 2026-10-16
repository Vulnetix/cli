<?php
// PHP 7 removed preg_replace('/x/e', ...); we migrated to preg_replace_callback.
$note = "Do not use preg_replace('/(.*)/e', '\\1', \$x) any more";
echo $note;
