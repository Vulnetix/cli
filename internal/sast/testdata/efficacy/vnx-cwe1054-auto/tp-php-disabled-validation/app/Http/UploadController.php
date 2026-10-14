<?php

class UploadController
{
    public function store($request)
    {
        $file = $request->file('document');
~>        // if (!in_array($file->extension(), ['pdf', 'png'])) {
        //     return response('unsupported type', 415);
        // }
        // $file = $this->scanner->clean($file);
        return $file->store('uploads');
    }
}
