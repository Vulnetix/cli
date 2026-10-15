<?php
$pattern = '[0-9]+';
$text = $_POST['text'] ?? '';
$flags = $_REQUEST['flags'];

~>echo mb_ereg_replace($pattern, '#', $text, $flags);

~>echo mb_eregi_replace($pattern, '*', $text, filter_input(INPUT_GET, 'opt'));
