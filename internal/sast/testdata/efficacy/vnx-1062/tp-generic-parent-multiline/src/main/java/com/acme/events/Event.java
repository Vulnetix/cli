package com.acme.events;

public class Event<T> {
    protected T payload;

    public boolean isAudit(Object o) {
~>        return o instanceof AuditEvent a && a.payload != null;
    }
}
