<?php

$ext = 'bin';
$dest = 'uploads/' . bin2hex(random_bytes(12)) . '.dat';
move_uploaded_file($_FILES['f']['tmp_name'], $dest);
$file->move(public_path('docs'), uuid() . '.pdf');
$request->file('x')->store('files');
