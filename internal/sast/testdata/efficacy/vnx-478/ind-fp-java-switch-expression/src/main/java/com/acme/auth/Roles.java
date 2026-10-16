package com.acme.auth;

public class Roles {
    enum Level { READER, WRITER, ADMIN }

    public String roleFor(Level level) {
        String role = null;
        role = switch (level) {
            case READER -> "reader";
            case WRITER -> "writer";
            case ADMIN -> "admin";
        };
        return role.toUpperCase();
    }
}
