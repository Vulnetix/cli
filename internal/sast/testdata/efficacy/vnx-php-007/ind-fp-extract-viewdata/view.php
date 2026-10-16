<?php
function render($file, array $data) {
    extract($data);
    include $file;
}
$row = $stmt->fetch(PDO::FETCH_ASSOC);
extract($row);
