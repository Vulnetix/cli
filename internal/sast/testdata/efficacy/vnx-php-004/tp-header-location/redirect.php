<?php
if (isset($_GET["url"])) {
~>    header("Location: " . $_GET["url"]);
    exit;
}
~>header ("location: " . $_REQUEST["to"]);
~>header("Location: {$_POST["dest"]}", true, 302);
~>header('Location: '.$_GET['next']);
