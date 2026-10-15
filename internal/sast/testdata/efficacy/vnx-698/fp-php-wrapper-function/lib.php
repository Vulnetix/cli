<?php
function redirect_to($url) {
    header("Location: " . $url);
}

function send_location($url)
{
    header('Location: ' . $url, true, 302);
}

redirect('/home');
