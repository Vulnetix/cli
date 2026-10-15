package com.acme;

public class Access {
    String level(User u) {
        if (u.isAdmin()) {
            return "admin";
        } else if (u.isEditor()) {
            return "editor";
~>        } else if (u.isAdmin()) {
            return "never";
        }
        return "none";
    }
}
