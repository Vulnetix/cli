<?php
$id = $_GET['id'];
$post = load_post($id);
$sid = session_id();
if (session_id() === '') {
    session_start();
}
