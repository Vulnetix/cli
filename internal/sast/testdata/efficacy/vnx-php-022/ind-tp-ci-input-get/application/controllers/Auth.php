<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Auth extends CI_Controller
{
    public function done()
    {
~>        redirect($this->input->get('return'));
    }
}
