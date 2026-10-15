package com.acme.auth;

public class Roles {
    String permissions(int level) {
        String role = null;
~>        switch (level) {
            case 1:
                role = "reader";
                break;
            case 2:
                role = "writer";
                break;
        }
        return role.toUpperCase();
    }

    String grant(Kind kind) {
        String scope = null;
~>        switch (kind) {
            case READ -> scope = "read";
            case WRITE -> scope = "write";
        }
        return scope.trim();
    }
}
