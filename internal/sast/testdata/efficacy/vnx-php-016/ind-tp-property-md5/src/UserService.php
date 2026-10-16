<?php

class UserService {
    public function register($input) {
        $user = new User();
~>        $user->password = md5($input['secret']);
        $user->save();
    }
}
