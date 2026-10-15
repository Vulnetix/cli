<?php
~>require_once "modules/{$_REQUEST['mod']}.inc.php";
~>$tpl = file_get_contents("templates/" . $_POST['theme'] . '/layout.html');
