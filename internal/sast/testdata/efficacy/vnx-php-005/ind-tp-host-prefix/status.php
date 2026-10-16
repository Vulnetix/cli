<?php
~>$data = file_get_contents("http://" . $_GET["h"] . "/status");
echo $data;
