<?php
// header('Location: ' . $_GET['url']); is an open redirect
/* return redirect($request->input('next')); */
$msg = 'Do not call header("Location: " . $_GET["u"])';
echo "redirect(\$_GET['next']) is unsafe";
