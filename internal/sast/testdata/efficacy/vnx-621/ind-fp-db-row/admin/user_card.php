<?php
$stmt = $pdo->prepare('SELECT name, email, joined FROM users WHERE id = ?');
$stmt->execute([(int) ($_GET['id'] ?? 0)]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);
if ($row) {
    extract($row);
    echo "<h2>" . htmlspecialchars($name) . "</h2>";
}
