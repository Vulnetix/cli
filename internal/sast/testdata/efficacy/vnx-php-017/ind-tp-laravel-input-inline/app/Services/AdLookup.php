<?php

namespace App\Services;

use Illuminate\Http\Request;

class AdLookup
{
    public function byAccount(Request $request, $ds)
    {
        $base = config('ldap.base_dn');
~>        $sr = ldap_search($ds, $base, '(sAMAccountName=' . $request->input('account') . ')');
        return ldap_get_entries($ds, $sr);
    }
}
