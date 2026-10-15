<?php
$stmt = $pdo->prepare('SELECT * FROM users WHERE name = ?');
$stmt->execute([$_POST['user']]);
$row = $stmt->fetch();
~>if ($row && $row['password'] == $_POST['password']) {
    $_SESSION['user'] = $row['name'];
}
~>if ($user->password === $password) {
    echo "welcome";
}
