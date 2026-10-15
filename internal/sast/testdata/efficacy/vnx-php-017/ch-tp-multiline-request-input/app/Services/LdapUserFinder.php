<?php

namespace App\Services;

use Illuminate\Http\Request;

class LdapUserFinder
{
    public function byEmail(Request $request)
    {
~>        $result = ldap_search(
            $this->connection,
            $this->baseDn,
            '(mail=' . $request->input('email') . ')'
        );

        return $result;
    }
}
