<?php
class DocController
{
    public function store(Request $request)
    {
        $request->validate(['doc' => 'required|file|mimes:pdf,docx|max:2048']);
        $file = $request->file('doc');
        $name = time() . '.' . $file->guessExtension();
        $file->move(storage_path('docs'), $name);

        $img = $request->file('img');
        $ext = strtolower($img->getClientOriginalExtension());
        if (!in_array($ext, ['jpg', 'png'], true)) {
            abort(422);
        }
        $img->move(public_path('img'), uniqid() . '.' . $ext);

        $cursor->move($request->input('offset'), 10);
    }
}
