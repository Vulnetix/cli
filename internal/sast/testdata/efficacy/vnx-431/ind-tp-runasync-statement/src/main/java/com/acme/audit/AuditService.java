package com.acme.audit;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

public class AuditService {
    private final AuditLog auditLog;
    private final Executor auditPool;

    public AuditService(AuditLog auditLog, Executor auditPool) {
        this.auditLog = auditLog;
        this.auditPool = auditPool;
    }

    public void record(AuditEvent event) {
        validate(event);
~>        CompletableFuture.runAsync(() -> auditLog.append(event.toRecord()), auditPool);
    }
}
