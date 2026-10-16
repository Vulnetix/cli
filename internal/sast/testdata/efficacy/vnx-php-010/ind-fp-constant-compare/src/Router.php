<?php

$action = $_GET['action'];
if ($action == 'login') { show_login(); }
if ($_POST['mode'] != "admin") { deny(); }
if ($count == 0) { empty_state(); }
if ($status == $other) { same(); }
