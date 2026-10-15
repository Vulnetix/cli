<?php

function next_reset_code(PDO $db): int
{
    $lastCode = (int) $db->query('SELECT MAX(code) FROM resets')->fetchColumn();
~>    $resetCode = $lastCode + 1;
    return $resetCode;
}
