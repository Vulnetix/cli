package com.acme.auth;

public class RoleCheck {
    boolean isAdmin(String role) {
~>        if (role == "admin") {
            return true;
        }
~>        return "superuser" != role ? false : true;
    }

    boolean emptyName(String name) {
~>        return name=="";
    }
}
