<?php
namespace Legacy\Text;

class Formatter
{
    public function titleCase(string $text): string
    {
~>        return mb_ereg_replace('(\w+)', 'ucfirst("\\1")', $text, 'msre');
    }

    public function shout(string $text): string
    {
~>        return \mb_eregi_replace("([a-z]+)", "strtoupper('\\1')", $text, "ie");
    }
}
