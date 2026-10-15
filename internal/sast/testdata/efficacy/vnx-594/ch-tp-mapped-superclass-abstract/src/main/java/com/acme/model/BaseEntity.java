package com.acme.model;

import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;

@MappedSuperclass
~>public abstract class BaseEntity {
    @Id
    protected Long id;
}
