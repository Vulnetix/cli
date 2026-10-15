package com.acme;

import java.util.*;

@Entity
~>public class Order implements Serializable {
    @ManyToOne
    private Customer customer;
    private Address shipping;
    private Address billing;
    private List<LineItem> items;
    private Map<String, Coupon> coupons;
    private Optional<GiftCard> giftCard;
    private Payment payment;
    private Invoice invoice;
    private Set<Tag> tags;
    private Warehouse warehouse;
    private Carrier carrier;
    private long id;
    private String note;

    public Order() {}
}
