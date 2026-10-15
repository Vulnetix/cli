<?php
$reader = new XMLReader();
$reader->open($file);
$reader->setParserProperty(XMLReader::VALIDATE, true);
$reader->setParserProperty(XMLReader::SUBST_ENTITIES, false);
