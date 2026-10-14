<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class DirectoryController extends Controller
{
    public function search(Request $request)
    {
        $ds = ldap_connect(config('ldap.host'));
        $term = $request->input('q');
~>        $sr = ldap_search(
            $ds,
            config('ldap.base_dn'),
            '(|(cn=*' . $term . '*)(mail=*' . $term . '*))'
        );
        return response()->json(ldap_get_entries($ds, $sr));
    }
}
