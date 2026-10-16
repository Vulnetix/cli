<?php
// $_COOKIE['user_id'] is never trusted here; identity comes from $_SESSION.
$theme = $_COOKIE['theme'] ?? 'light';
$csrf = $_COOKIE['XSRF-TOKEN'] ?? '';
?>
<header class="<?= htmlspecialchars($theme) ?>">
  <span>Welcome back, <?= htmlspecialchars($_COOKIE['username'] ?? 'guest', ENT_QUOTES) ?></span>
</header>
