package com.acme.web;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.RequestScoped;
import jakarta.persistence.PrePersist;

// @Entity was removed from this class when it stopped being persisted.
@RequestScoped
public class RequestTimer {

    private final long startedAt = System.nanoTime();

    public long elapsedNanos() {
        return System.nanoTime() - startedAt;
    }
}

@ApplicationScoped
class MetricsRegistry {

    private long requests;

    void increment() {
        requests++;
    }
}

class AuditListener {

    @PrePersist
    void stamp(Object entity) {
    }
}

enum OrderStatus {
    OPEN, PAID, SHIPPED
}
