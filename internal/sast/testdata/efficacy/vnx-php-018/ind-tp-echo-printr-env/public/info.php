<?php
header('Content-Type: text/html');
echo '<h1>Environment</h1>';
~>echo '<pre>' . print_r($_ENV, true) . '</pre>';
