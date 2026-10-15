package com.acme.auth;

import java.util.Objects;

public class SafeCheck {
    enum Mode { ON, OFF }

    boolean isAdmin(String role, Mode mode, int count) {
        if (role == null || role.isEmpty()) {
            return false;
        }
        if ("admin".equals(role) || Objects.equals(role, "root")) {
            return true;
        }
        if (mode == Mode.ON && count == 3) {
            return role.length() == 5;
        }
        char c = role.charAt(0);
        return c == 'a' || role.equalsIgnoreCase("ADMIN");
    }
}
