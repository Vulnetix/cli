<?php
class Settings extends CI_Controller
{
    public function save()
    {
~>        $this->session->set_userdata($this->input->post('setting'), $this->input->post('value'));
    }

    public function legacy()
    {
        $slot = filter_input(INPUT_POST, 'slot');
        if ($slot !== null) {
~>            $_SESSION[$slot] = $_POST['payload'];
        }
    }
}
