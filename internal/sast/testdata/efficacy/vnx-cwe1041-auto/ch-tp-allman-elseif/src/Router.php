<?php
class Router
{
    public function dispatch($role, $path)
    {
        if ($role == 'admin')
        {
            return $this->admin($path);
        }
~>        elseif ($role == 'admin')
        {
            return $this->auditor($path);
        }
        return $this->guest($path);
    }
}
