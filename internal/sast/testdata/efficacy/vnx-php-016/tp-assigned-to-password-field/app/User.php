<?php

class UserFactory
{
    public function make(array $input)
    {
        $user = new User();
~>        $user->password = md5($input['secret']);
~>        $hashedPassword = sha1($input['pw']);
        return [
~>            'password' => md5($input['p']),
            'name' => $input['name'],
        ];
    }
}
