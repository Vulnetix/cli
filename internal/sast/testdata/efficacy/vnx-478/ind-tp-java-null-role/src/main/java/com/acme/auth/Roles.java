package com.acme.auth;

public class Roles {
    public String roleFor(int level) {
        String role = null;
~>        switch (level) {
            case 1:
                role = "reader";
                break;
            case 2:
                role = "writer";
                break;
            case 3:
                role = "admin";
                break;
        }
        return role.toUpperCase();
    }
}
