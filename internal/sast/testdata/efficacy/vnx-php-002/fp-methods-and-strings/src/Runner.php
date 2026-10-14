<?php
// Never call system($_GET["cmd"]) here.
class Runner
{
    public function exec($command)
    {
        return $this->process->exec($_POST["command"]);
    }

    public static function system($x) {}
}

$db->exec("DELETE FROM sessions WHERE id = " . $id);
$pdo->exec($_POST["sql"]);
Runner::system($_GET["q"]);
echo "Do not use shell_exec(\$_GET) in production";
$msg = "exec(" . $_GET["x"] . ")";
$help = 'Run system($_GET["cmd"]) to see';
