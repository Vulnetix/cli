<?php
namespace App\Lib;

class Template
{
    public function render(string $tpl, array $vars): string
    {
~>        return preg_replace("#\{(\w+)\}#e", '$vars["$1"]', $tpl);
    }
}
