package com.acme.shop;

import java.io.Serializable;
import java.util.List;
import javax.persistence.*;

@Entity
@Table(name = "orders")
~>public class Order
        extends AuditedEntity
        implements Serializable, Comparable<Order> {

    @Id
    private Long id;

    @ManyToOne
    private Customer customer;

    @ManyToOne
    private Address billingAddress;

    @ManyToOne
    private Address shippingAddress;

    @OneToMany(mappedBy = "order")
    private List<OrderLine> lines;

    @OneToOne
    private Payment payment;

    @OneToOne
    private Invoice invoice;

    @ManyToOne
    private Warehouse warehouse;

    @ManyToOne
    private Carrier carrier;

    @OneToMany
    private List<Shipment> shipments;

    @ManyToOne
    private Coupon coupon;

    @ManyToOne
    private SalesChannel channel;

    private String note;

    public int compareTo(Order other) {
        return id.compareTo(other.id);
    }
}
