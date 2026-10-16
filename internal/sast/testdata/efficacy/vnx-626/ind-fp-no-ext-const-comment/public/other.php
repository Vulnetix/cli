<?php
include('config/' . 'app' . '.php');
// include($_GET['page'] . '.php');
$msg = "include($_GET['page'] . '.php') is dangerous";
readfile($_GET['file']);
