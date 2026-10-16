package com.acme.security;

import java.security.Principal;

public final class PrincipalCheck {

    static boolean isServiceAccount(Principal p) {
        String kind = p.getClass().getCanonicalName();
        if (kind == null) {
            return false;
        }
~>        return kind.equals("com.acme.security.ServicePrincipal");
    }

    static boolean isAdmin(Object o) {
~>        return o.getClass().getSimpleName() == "AdminPrincipal";
    }
}
