<?php
header('Location: /dashboard');
header("Location: /login?next=" . urlencode($_GET['next']));
header('Location: https://accounts.example.com/callback?state=' . $_GET['state']);
header('Location: index.php?page=' . (int) $_GET['page']);
$base = getenv('APP_URL');
header('Location: ' . $base . '/home');
