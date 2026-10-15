package com.shop.domain;

import javax.persistence.Entity;

@Entity
public class Invoice extends BaseEntity {
    private String number;
}

@Entity
public record Line(Long id) implements java.io.Serializable {
}
