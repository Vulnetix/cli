<?php
$id = $_GET["id"];
header("Location: /profile.php?id=" . urlencode($id));
header("Location: https://shop.example.com/item/" . $_GET["sku"]);
header("Location: /login?next=" . rawurlencode($_REQUEST["next"]));
header("Location: info.php?id=" . $_GET["page"]);
header("Location: /");
header("Location: " . $baseUrl . "/home");
