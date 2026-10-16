<?php

class ImgController extends Controller {
    public function store(Request $request) {
~>        $request->file('img')->storeAs('images', $request->file('img')->getClientOriginalName());
    }
}
