package com.acme;

import java.util.Optional;

public class Lookup {
    public String owner(Account a) {
        return Optional.ofNullable(a)
            .map(Account::getOwner)
            .map(Owner::getName)
            .orElse("unknown");
    }

    public void load(String id) {
        try {
            repo.load(id);
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new LookupException("bad id " + id, e);
        }
    }
}
