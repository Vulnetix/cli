<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class DirectoryController extends Controller
{
    public function show(Request $request)
    {
        $sr = ldap_search($this->ds, $this->base, '(uid=' . ldap_escape($request->input('u'), '', LDAP_ESCAPE_FILTER) . ')');
        $id = (int) $request->query('id');
        $byNumber = ldap_search($this->ds, $this->base, "(uidNumber=$id)");
        return [$sr, $byNumber];
    }
}
