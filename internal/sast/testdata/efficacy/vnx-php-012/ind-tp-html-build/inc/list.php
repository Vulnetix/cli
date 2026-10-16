<?php

$html = '<ul>';
$tag = $_GET['tag'];
~>$html .= '<li>' . $tag . '</li>';
$html .= '</ul>';
echo $html;
