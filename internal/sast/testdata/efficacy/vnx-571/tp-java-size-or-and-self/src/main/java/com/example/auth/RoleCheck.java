package com.example.auth;

import java.util.List;

public class RoleCheck {
    static final int ROLE_ADMIN = 1;
    static final int ROLE_OWNER = 2;

    public boolean mayDelete(int role, List<String> grants, String[] scopes) {
~>        if (role != ROLE_ADMIN || role != ROLE_OWNER) {
            return false;
        }
~>        if (grants.size() >= 0 && scopes.length >= 0) {
            return true;
        }
        return false;
    }

    public boolean sameTenant(Tenant mine, Tenant other) {
~>        return mine.id == mine.id;
    }

    public boolean code(int status) {
~>        return status != 200 || status != 204;
    }
}
