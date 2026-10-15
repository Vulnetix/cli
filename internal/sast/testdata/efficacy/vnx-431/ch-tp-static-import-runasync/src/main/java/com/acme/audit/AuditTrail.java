package com.acme.audit;

import static java.util.concurrent.CompletableFuture.runAsync;

public class AuditTrail {
    private final AuditStore store;

    public AuditTrail(AuditStore store) {
        this.store = store;
    }

    public void record(Event e) {
~>        runAsync(() -> store.append(e));
    }
}
