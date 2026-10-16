<?php
class Auth extends CI_Controller
{
    public function login()
    {
        $return = $this->input->get('return');
~>        redirect($return);
    }
}
