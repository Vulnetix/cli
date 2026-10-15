<?php
function byName(array $a, array $b): int
{
    return strcmp($a['name'], $b['name']);
}

function sameToken(string $expected): bool
{
    return strcmp((string) ($_POST['token'] ?? ''), $expected) === 0;
}

usort($rows, 'byName');
$isDefault = strcmp($config['theme'], 'default') == 0;
