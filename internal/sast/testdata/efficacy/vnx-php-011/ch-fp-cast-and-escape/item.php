<?php
$id = (int) $_GET['id'];
$db->query("SELECT * FROM items WHERE id = $id");
$n = intval($_GET['n']);
$db->query("SELECT * FROM items LIMIT " . $n);
mysqli_query($c, "SELECT * FROM t WHERE name = '" . mysqli_real_escape_string($c, $_POST['name']) . "'");
