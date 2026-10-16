package com.acme.persistence;

import java.time.Instant;
import javax.persistence.Column;
import javax.persistence.MappedSuperclass;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;

@MappedSuperclass
~>public abstract class AuditedEntity {

    @Column(name = "created_at", updatable = false)
    protected Instant createdAt;

    @Column(name = "updated_at")
    protected Instant updatedAt;

    @PrePersist
    void onCreate() {
        createdAt = Instant.now();
        updatedAt = createdAt;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }
}
