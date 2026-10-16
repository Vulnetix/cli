package com.acme.auth;

public class RoleCheck {
    static final String ROLE_ADMIN = "admin";
    static final String ROLE_OWNER = "owner";

    boolean deny(String role, int port) {
        // never write: role != ROLE_ADMIN || role != ROLE_OWNER
        if (!ROLE_ADMIN.equals(role) && !ROLE_OWNER.equals(role)) {
            return true;
        }
        return port > 1024 && port < 65535;
    }
}
