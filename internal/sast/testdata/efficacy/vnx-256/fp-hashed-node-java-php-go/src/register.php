<?php
$user->password = password_hash($_POST['password'], PASSWORD_DEFAULT);
$user->password = Hash::make($request->input('password'));
