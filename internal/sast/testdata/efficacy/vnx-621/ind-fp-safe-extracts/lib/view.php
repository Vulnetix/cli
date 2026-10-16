<?php
function render($template, array $data) {
    extract($data, EXTR_SKIP);
    include $template;
}

function prefixed() {
    extract($_POST, EXTR_PREFIX_ALL, 'form');
    return $form_name;
}

$row = $stmt->fetch(PDO::FETCH_ASSOC);
extract($row);
