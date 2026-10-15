<?php
class SsoController
{
    public function resume(Request $request)
    {
~>        $request->session()->setId($request->input('sid'));
        $request->session()->start();
    }

    public function legacy()
    {
        $sid = $_REQUEST['PHPSESSID'];
~>        session_id( $sid );
        session_start();
    }
}
