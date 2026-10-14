<?php
function calculate() {
    $expr = $_GET["expr"];
~>    eval("\$result = " . $expr . ";");
    return $result;
}

$file = $_GET["file"];
~>$listing = `ls -l $file`;
echo $listing;
