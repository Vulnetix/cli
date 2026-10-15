<?php
class Installer
{
    public function writeProbe(string $dir): void
    {
        $code = <<<'PHP'
<?php
phpinfo();
PHP;
        file_put_contents($dir . '/probe.php', $code);
    }
}
