<?php
class Templater
{
    public function boot(): void
    {
~>        mb_regex_set_options("msre");
    }

    public function render(string $tpl, array $vars): string
    {
~>        return mb_ereg_replace(
            '\{(\w+)\}',
            '$vars["\\1"]',
            $tpl,
            'e'
        );
    }
}
