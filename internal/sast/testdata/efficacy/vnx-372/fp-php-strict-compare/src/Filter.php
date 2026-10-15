<?php
class Filter
{
    public function isAdmin($email)
    {
        if (strpos($email, 'admin@') !== false) {
            return true;
        }
        if (strpos($email, 'root') === 0) {
            return true;
        }
        $at = strpos($email, '@');
        if ($at > 0 && str_contains($email, '.')) {
            return false;
        }
        return stripos($email, 'test') === false;
    }
}
