<?php

class Settings extends CI_Controller
{
    public function save()
    {
        $field = $this->input->post('field') ?: $_POST['field'];
~>        $this->session->set_userdata($field, $_POST['value']);
    }

    public function symfony($request, $session)
    {
        $opt = $request->get('opt');
~>        $session->set($opt, true);
~>        Session::put($request->input('k'), 1);
        $this->session->set_userdata('theme', $request->get('theme'));
        Session::put('locale', $request->input('locale'));
    }
}
