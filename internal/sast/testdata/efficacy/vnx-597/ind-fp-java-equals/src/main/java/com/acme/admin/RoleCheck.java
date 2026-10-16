package com.acme.admin;

import java.util.Objects;

public class RoleCheck {

    public boolean isAdmin(String role) {
        if (role == null) {
            return false;
        }
        return "admin".equals(role) || Objects.equals(role, "root") || role.equalsIgnoreCase("OWNER");
    }

    public boolean isSeparator(char c) {
        return c == '/' || c == '\\';
    }

    public boolean sameInstance(Object a, Object b) {
        return a == b;
    }

    public String describe() {
        return "use equals, not role == \"admin\"";
    }
}
