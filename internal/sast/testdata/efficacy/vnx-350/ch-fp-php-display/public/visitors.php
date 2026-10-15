<?php
foreach ($visits as $visit) {
    $host = gethostbyaddr($visit['ip']);
    echo '<tr><td>' . htmlspecialchars($visit['ip']) . '</td>';
    echo '<td>' . htmlspecialchars($host ?: 'unknown') . '</td></tr>';
}
