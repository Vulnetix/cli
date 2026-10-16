<?php

class ItemController extends Controller {
    public function index(Request $request) {
~>        return DB::select("SELECT * FROM items WHERE owner = " . $_GET['owner']);
    }
}
