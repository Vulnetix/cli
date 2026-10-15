<?php
class View
{
    public function render(string $template, array $data): string
    {
        extract($data);
        ob_start();
        include $template;
        return ob_get_clean();
    }
}

$row = $stmt->fetch(PDO::FETCH_ASSOC);
extract($row);

$defaults = ['title' => 'Home', 'lang' => 'en'];
extract($defaults);
