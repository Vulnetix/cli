<?php

class DocController extends Controller {
    public function store(Request $request) {
        $file = $request->file('doc');
~>        $file->move(public_path('docs'), $file->getClientOriginalName());
    }
}
