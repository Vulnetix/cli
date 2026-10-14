<?php
exec("git rev-parse HEAD", $out);
$version = shell_exec("php -v");
system("composer dump-autoload");

function runCommand(string $cmd): string
{
    return shell_exec($cmd);
}

$cfg = require __DIR__ . "/config.php";
passthru($cfg["deploy_command"]);
eval("return 1 + 2;");
