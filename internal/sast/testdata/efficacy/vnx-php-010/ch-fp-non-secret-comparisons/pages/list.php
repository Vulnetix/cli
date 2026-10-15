<?php
$currentPage = 3;
if ($_GET['page'] == $currentPage) {
    echo 'active';
}
if (strlen($_POST['password']) == 0) {
    $errors[] = 'Password required';
}
if ($_POST['sort'] == $defaultSort) {
    $sort = 'name';
}
