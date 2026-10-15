package com.acme;

public class Roles {
    String permissions(int level) {
        String role = "guest";
        switch (level) {
            case 1:
                role = "reader";
                break;
            case 2:
                role = "writer";
                break;
        }
        return role;
    }
}
