<?php
$src = $_GET['src'];
~>copy($src, '/tmp/thumb-source');
~>$img = imagecreatefromjpeg($_REQUEST['image']);
