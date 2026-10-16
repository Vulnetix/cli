package com.acme.orders;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.Instant;

@Entity
@Table(name = "orders")
@NamedQuery(name = "Order.byCustomer", query = "select o from Order o where o.customerId = :cid")
~>public class Order {

    @Id
    @GeneratedValue
    private Long id;

    @Column(nullable = false)
    private Long customerId;

    private BigDecimal total;

    private Instant placedAt;

    protected Order() {
    }

    public Long getId() {
        return id;
    }
}
