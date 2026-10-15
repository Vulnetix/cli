<?php
require __DIR__ . '/../bootstrap.php';

$price = lookup_price($sku ?? 'basic');
~>extract(array_merge($_GET, $_POST), EXTR_OVERWRITE);
~>extract(array_map('trim', $_REQUEST));

$total = $price * (int) $quantity;
render('order', compact('total'));
