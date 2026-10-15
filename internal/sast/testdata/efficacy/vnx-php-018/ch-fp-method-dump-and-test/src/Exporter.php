<?php
class Exporter
{
    public function export()
    {
        return $this->dumper->dump($_SERVER);
    }

    public static function snapshot()
    {
        return Yaml::dump($_ENV);
    }
}
