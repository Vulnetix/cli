<?php
function render_theme($request)
{
    $theme = $request->input("theme");
    $path = "themes/" . $theme . "/layout.php";
~>    require $path;
}

$skin = $_SERVER["HTTP_X_SKIN"];
~>include
    "skins/" . $skin;
