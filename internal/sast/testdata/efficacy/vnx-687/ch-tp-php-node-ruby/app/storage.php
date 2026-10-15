<?php
function prepare($dir, $file) {
~>    mkdir($dir, 755, true);
~>    chmod($file, 644);
}
