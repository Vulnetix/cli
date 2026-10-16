package com.acme.account;

import java.util.Iterator;
import java.util.List;

public final class ReadOnlyRoleList implements Iterable<String> {

    private final List<String> roles;

    public ReadOnlyRoleList(List<String> roles) {
        this.roles = List.copyOf(roles);
    }

    @Override
    public Iterator<String> iterator() {
        Iterator<String> it = roles.iterator();
        return new Iterator<>() {
            public boolean hasNext() { return it.hasNext(); }
            public String next() { return it.next(); }
            public void remove() {
                throw new UnsupportedOperationException("roles are read-only");
            }
        };
    }
}
