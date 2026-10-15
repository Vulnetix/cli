<?php
// LIBXML_NOENT enables entity substitution, never pass it to loadXML().
$warning = 'Do not call loadXML($x, LIBXML_NOENT) on untrusted input';
echo $warning;
