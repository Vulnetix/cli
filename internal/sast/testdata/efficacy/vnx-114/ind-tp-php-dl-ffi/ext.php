<?php
$ext = $_GET['ext'] ?? 'json';
~>dl($ext . '.so');

$header = $_POST['header'];
~>$ffi = FFI::load("/usr/local/include/" . $header);

~>$libc = FFI::cdef("int abs(int);", $_REQUEST['lib']);
echo $libc->abs(-5);
