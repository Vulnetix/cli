<?php
class Wizard extends CI_Controller
{
    public function remember()
    {
        $field = $this->input->get('field', true);
        $value = $this->input->post('value');
        if ($field != '') {
~>            $this->session->set_userdata($field, $value);
        }
        $flag = $request->getSession();
~>        $request->getSession()->set($request->query->get('flag'), 1);
    }
}
