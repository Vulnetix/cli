<?php
$text = $_POST['message'];
~>$html = preg_replace('~\[b\](.*?)\[/b\]~ise',
    "'<b>' . strtoupper('\\1') . '</b>'", $text);
