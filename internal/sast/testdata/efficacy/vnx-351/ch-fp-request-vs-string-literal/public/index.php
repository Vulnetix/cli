<?php
$page = $_GET['page'] ?? 'home';
if ($page == 'home') {
    include 'home.php';
} elseif (in_array($page, ['about', 'contact', 'faq'])) {
    include $page . '.php';
}
// in_array($_GET['id'], $ids) would be loose; we use strict mode elsewhere.
echo "<p>Use in_array(\$x, \$list, true) for ids</p>";
