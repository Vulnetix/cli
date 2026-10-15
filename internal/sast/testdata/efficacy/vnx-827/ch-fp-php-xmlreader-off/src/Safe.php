<?php

$reader = new XMLReader();
$reader->open('feed.xml');
$reader->setParserProperty(XMLReader::LOADDTD, false);
$reader->setParserProperty(XMLReader::SUBST_ENTITIES, false);
// $reader->setParserProperty(XMLReader::LOADDTD, true);
$help = 'call setParserProperty(XMLReader::LOADDTD, true) only for trusted feeds';
