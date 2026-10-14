<?php
class View
{
    public function render(string $template, array $data): string
    {
        extract($data, EXTR_SKIP);
        ob_start();
        include $template;
        return ob_get_clean();
    }
}

$row = $db->fetch("SELECT * FROM settings");
extract($row);
foreach ($config as $name => $value) {
    $$name = $value;
}
