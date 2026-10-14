<?php
function update_profile($request)
{
    $fields = $request->all();
~>    extract($fields);
~>    extract($request->input());
    save_user($name, $email);
}

$data = json_decode(file_get_contents("php://input"), true);
~>extract($data);
