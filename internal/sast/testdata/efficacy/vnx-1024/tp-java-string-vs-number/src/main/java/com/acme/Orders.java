package com.acme;

import java.util.Objects;

public class Orders {
    public boolean isAdmin(String role, String level) {
~>        if (level.equals(1)) {
            return true;
        }
~>        return Objects.equals(role, 0) || "1".equals(1);
    }

    public boolean active(String flag) {
~>        return flag.equals(true);
    }
}
