package com.acme;

public class Access {
    public Level levelFor(User user) {
        if (user.hasRole("ADMIN")) {
            return Level.FULL;
        } else if (user.hasRole("SUPPORT")) {
            return Level.READ;
~>        } else if (user.hasRole("ADMIN")) {
            return Level.AUDIT;
        }
        return Level.NONE;
    }
}
