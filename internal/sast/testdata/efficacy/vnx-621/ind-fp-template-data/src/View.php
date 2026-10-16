<?php

class View
{
    private $vars = [];

    public function render($template, array $data = [])
    {
        $data = array_merge($this->vars, $data);
        extract($data);
        ob_start();
        include __DIR__ . '/../templates/' . $template . '.php';
        return ob_get_clean();
    }
}
