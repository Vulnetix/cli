package com.acme.shop;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "orders")
~>public class Order implements Comparable<Order> {
    @Id
    private Long id;

    public int compareTo(Order o) {
        return id.compareTo(o.id);
    }
}
