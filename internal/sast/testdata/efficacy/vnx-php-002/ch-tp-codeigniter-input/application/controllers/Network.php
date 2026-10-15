<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Network extends CI_Controller
{
    public function lookup()
    {
        $host = $this->input->post('host');
        $out = [];
~>        exec("nslookup " . $host, $out, $status);
        $this->load->view('network/lookup', ['out' => $out]);
    }
}
