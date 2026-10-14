<?php
// header("Location: " . $_GET["url"]);  -- vulnerable, do not do this
echo "Example: header(\"Location: \" . \$_GET[\"url\"])";
$msg = "redirect($_GET) is unsafe";
/* return redirect($request->input("next")); */
