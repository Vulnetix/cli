<?php
class AvatarController
{
    public function store(Request $request)
    {
        $file = $request->file('avatar');
        $name = time() . '.' . $file->getClientOriginalExtension();
~>        $file->move(public_path('avatars'), $name);
    }
}
