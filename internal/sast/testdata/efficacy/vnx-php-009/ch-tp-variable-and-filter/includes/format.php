<?php
function format_numbers($body)
{
    $pattern = '/(\d+)/me';
    $replacement = 'number_format("$1")';
~>    return preg_replace($pattern, $replacement, $body);
}

function legacy_filter($items)
{
~>    return preg_filter('~\$(\w+)~se', '$GLOBALS["$1"]', $items);
}
