<?php
$data = json_decode($_POST["data"], true);
$s = serialize($data);
// unserialize($_COOKIE["x"]) is unsafe
