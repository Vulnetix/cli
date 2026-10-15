<?php
$reader = new XMLReader();
$reader->open($file);
~>$reader->setParserProperty(XMLReader::SUBST_ENTITIES, true);
while ($reader->read()) {
    handle($reader);
}
