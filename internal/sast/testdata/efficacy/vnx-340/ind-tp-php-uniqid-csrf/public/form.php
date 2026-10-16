<?php
session_start();

if (empty($_SESSION['csrf_token'])) {
~>    $_SESSION['csrf_token'] = sha1(uniqid('', true));
}
?>
<form method="post" action="/transfer">
  <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
</form>
