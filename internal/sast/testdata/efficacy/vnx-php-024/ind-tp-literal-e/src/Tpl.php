<?php
function render(string $subject): string
{
~>    return mb_ereg_replace('\{\{(\w+)\}\}', '$vars["\1"]', $subject, 'e');
}
