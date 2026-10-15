package com.acme.audit;

import java.util.Date;
import java.util.Set;

public abstract class Event {
    protected Date created = new Date();
    private final Set<String> tags = new java.util.HashSet<>();

    protected Date getCreated() {
~>        return this.created;
    }

    public synchronized Set<String> tags() {
~>        return tags;
    }
}
