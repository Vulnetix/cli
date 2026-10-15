package com.acme.audit;

import javax.persistence.*;

@Entity @Table(name = "audit_event",
        indexes = { @Index(columnList = "createdAt") })
~>class Event {
    @Id
    @GeneratedValue
    private Long id;
}
