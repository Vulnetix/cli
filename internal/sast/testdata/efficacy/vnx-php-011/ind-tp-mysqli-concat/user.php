<?php

$id = $_GET['id'];
~>$res = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
while ($r = mysqli_fetch_assoc($res)) { echo htmlspecialchars($r['name']); }
