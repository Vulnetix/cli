<?php
function prepare($dir, $file) {
    mkdir($dir, 0755, true);
    chmod($file, 0644);
    $size = filesize($file) % 755;
}
