<?php

echo "Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo htmlentities($_REQUEST['q']);
$id = (int) $_GET['id'];
echo "Item $id";
$page = intval($_GET['page']);
echo "<p>Page " . $page . "</p>";
$safe = htmlspecialchars($_POST['comment'], ENT_QUOTES);
echo "<p>$safe</p>";
?>
<input value="<?= htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES) ?>">
<?php
echo json_encode(['q' => $_GET['q']]);
echo isset($_GET['debug']) ? 'on' : 'off';
echo count($_POST);
