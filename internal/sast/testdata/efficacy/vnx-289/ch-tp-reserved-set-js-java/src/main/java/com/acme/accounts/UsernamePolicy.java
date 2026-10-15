package com.acme.accounts;

import java.util.Set;

public final class UsernamePolicy {
    private static final Set<String> RESERVED = Set.of("admin", "root", "system");

    public void check(String login) {
~>        if (RESERVED.contains(login)) {
            throw new IllegalArgumentException("reserved name");
        }
    }
}
