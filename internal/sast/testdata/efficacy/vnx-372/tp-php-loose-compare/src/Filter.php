<?php
class Filter
{
    public function isAdmin($email)
    {
~>        if (strpos($email, 'admin@') == false) {
            return false;
        }
        return true;
    }

    public function starts($name)
    {
~>        return strpos($name, 'tmp_') == 0;
    }

    public function has($value)
    {
~>        if (stripos(strtolower($value), 'drop') != false) {
            return true;
        }
        return false;
    }
}
