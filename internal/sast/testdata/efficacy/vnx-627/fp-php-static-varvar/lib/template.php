<?php
function render(array $data) {
    foreach ($data as $key => $value) {
        $$key = $value;
    }
    $field = 'title';
    echo ${$field};
    echo $_GET['page'];
}
