<?php

$line = 'Web Server: <em>' . $_SERVER['SERVER_NAME'] . '</em>';
echo "<p>Root: {$_SERVER['DOCUMENT_ROOT']}</p>";
?>
<form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
