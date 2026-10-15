<?php
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo (int) $_GET['page'];
echo intval($_GET['id']);
echo htmlentities($_POST['comment']);
