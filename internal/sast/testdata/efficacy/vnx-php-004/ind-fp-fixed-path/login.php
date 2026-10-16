<?php
$next = $_GET["next"];
header("Location: /login?next=" . urlencode($next));
header("Location: https://shop.example.com/item/" . $_GET["sku"]);
header("Location: info.php?id=" . $_GET["id"]);
