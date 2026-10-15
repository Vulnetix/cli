package com.acme;

import java.util.Objects;

public class Orders {
    private Long ownerId;
    private Integer status;

    public boolean ok(String role, String level) {
        if (level.equals("1")) {
            return true;
        }
        // level.equals(1) would always be false
        String msg = "use level.equals(1) carefully";
        return Objects.equals(role, "admin") || ownerId.equals(0L) || status.equals(3);
    }
}
