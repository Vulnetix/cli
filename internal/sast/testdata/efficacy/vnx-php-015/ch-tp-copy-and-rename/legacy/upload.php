<?php
$f = $_FILES['attachment'];
~>copy($f['tmp_name'], 'attachments/' . $_FILES['attachment']['name']);
~>rename($_FILES['img']['tmp_name'], "img/" . $_FILES['img']['name']);
