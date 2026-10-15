<?php
// Do not write: str_replace('../', '', $path); it collapses "....//".
$hint = "never use str_replace('../', '', \$path)";
$path = realpath($base . '/' . $name);
