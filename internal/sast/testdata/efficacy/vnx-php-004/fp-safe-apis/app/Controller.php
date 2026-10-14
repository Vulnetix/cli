<?php
class Controller
{
    public function save($request)
    {
        wp_safe_redirect($_GET["redirect_to"]);
        return redirect()->route("dashboard", ["tab" => $request->input("tab")]);
    }

    public function back()
    {
        return redirect()->back();
    }

    public function home()
    {
        return redirect("/home");
    }

    public function out($user)
    {
        return redirect($user->homepage);
    }
}
