<?php

class Template
{
    private $vars = [];

    public function assign($name, $value)
    {
        $this->vars[$name] = $value;
    }

    public function fetch($tpl)
    {
        $vars = $this->vars;
~>        return preg_replace("/\{\{\s*(\w+)\s*\}\}/e", "\$vars['\\1']", $tpl);
    }
}
