package com.acme.user;

import java.util.Optional;

public class Lookup {

    public String name(Optional<User> u) {
        return u.isEmpty() ? "anonymous" : u.get().getName();
    }

    public String other(Optional<User> u) {
        if (!u.isPresent()) {
            return "none";
        }
        return u.get().getName();
    }
}
