<?php
$prefs = json_decode($_COOKIE['prefs'] ?? '{}', true); // was unserialize($_COOKIE['prefs'])
$theme = $prefs['theme'] ?? 'light'; # unserialize($_GET) removed
