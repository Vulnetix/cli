<?php
function prep($dir) {
~>    mkdir($dir, 755, true);
    mkdir($dir . "/ok", 0755, true);
}
