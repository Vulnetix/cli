<?php
if ($_POST['author'] != $post->author) {
    $post->author = $_POST['author'];
}
if ($_GET['hashtag'] == $currentTag) {
    $active = true;
}
if ($_POST['postcode'] != $address->postcode) {
    $changed = true;
}
if ($_GET['passenger'] == $booking->passenger) {
    $ok = 1;
}
if ($_GET['encoding'] == $defaultEncoding) {
    $enc = 'utf-8';
}
