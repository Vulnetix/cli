<?php
session_start();
~>$_SESSION['csrf'] = uniqid('', true);
~>setcookie('session', uniqid(), ['httponly' => true]);
