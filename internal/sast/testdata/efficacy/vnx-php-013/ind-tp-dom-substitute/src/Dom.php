<?php

$dom = new DOMDocument();
~>$dom->substituteEntities = true;
$dom->load($file);
