package com.acme;

import java.util.List;

public class Finder {
    User first(List<User> users, String n) {
        return users.stream()
            .filter(u -> u.name().equals(n))
            .findFirst()
~>            .get();
    }
}
