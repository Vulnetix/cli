<?php

$dir = 'uploads/';
~>move_uploaded_file($_FILES['f']['tmp_name'], $dir . $_FILES['f']['name']);
