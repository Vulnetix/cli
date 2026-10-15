<?php

namespace App\Console;

class GeneratorCommand
{
    protected function qualify($name)
    {
        if (str_ends_with($name, '.php')) {
            return substr($name, 0, -4);
        }
        return $name;
    }
}
