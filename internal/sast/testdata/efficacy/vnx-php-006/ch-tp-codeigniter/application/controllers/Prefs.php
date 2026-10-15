<?php
class Prefs extends CI_Controller
{
    public function index()
    {
~>        $prefs = unserialize($this->input->cookie('prefs'));
    }
}
