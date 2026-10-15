<?php

use Symfony\Config\FrameworkConfig;

return static function (FrameworkConfig $framework): void {
~>    $framework->csrfProtection()->enabled(false);
};
