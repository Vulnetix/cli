<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class LdapLoginController
{
    public function login(Request $request)
    {
        $username = $request->input('username');
        $password = $request->input('password');
        $conn = ldap_connect(config('ldap.host'));
        $dn = sprintf('uid=%s,ou=people,dc=corp,dc=example', ldap_escape($username, '', LDAP_ESCAPE_DN));

~>        if (@ldap_bind($conn, $dn, $password)) {
            auth()->loginUsingId($this->localId($username));
            return redirect('/');
        }

        return back()->withErrors(['username' => 'Invalid credentials']);
    }
}
