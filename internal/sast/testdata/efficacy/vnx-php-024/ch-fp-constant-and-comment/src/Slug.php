<?php
class Slug
{
    private const OPTIONS = 'msr';

    public function make(string $title): string
    {
        // mb_ereg_replace($p, $r, $s, 'e') used to evaluate the replacement
        $doc = "mb_ereg_replace('a', 'b', \$s, 'e')";
        return mb_ereg_replace('[^a-z0-9]+', '-', mb_strtolower($title), self::OPTIONS);
    }
}
