<?php
// $pass = md5($pass); was the old scheme
# md5($x) is not used any more

$sql = "SELECT id, md5(name) AS h FROM files WHERE owner = ?";
$help = 'Call md5() only for cache keys';
