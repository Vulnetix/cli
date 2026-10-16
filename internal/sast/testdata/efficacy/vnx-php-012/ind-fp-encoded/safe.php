<?php

echo "<h1>" . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8') . "</h1>";
echo '<p>' . htmlentities($_POST['x']) . '</p>';
echo (int) $_GET['n'];
echo json_encode(['q' => $_GET['q']]);
$safe = htmlspecialchars($_GET['t']);
echo "<i>$safe</i>";
