<?php
class Page extends CI_Controller
{
    public function show()
    {
        $name = $this->input->get('name');
~>        include APPPATH . 'pages/' . $name . '.php';
    }
}
