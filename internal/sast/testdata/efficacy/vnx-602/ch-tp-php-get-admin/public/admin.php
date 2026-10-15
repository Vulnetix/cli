<?php
require __DIR__ . '/../bootstrap.php';

~>if ($_GET['admin'] == 1) {
    echo render_admin_panel();
    exit;
}
http_response_code(403);
