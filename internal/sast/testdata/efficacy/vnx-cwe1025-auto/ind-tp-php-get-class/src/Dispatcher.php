<?php
class Dispatcher
{
    public function isAdmin($handler)
    {
~>        if (get_class($handler) == 'AdminHandler') {
            return true;
        }
        return false;
    }
}
