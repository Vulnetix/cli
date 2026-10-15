<?php
$_SESSION['login_attempts']++;
$token_uses += 1;
$_SESSION['views'] = $_SESSION['views'] + 1;
