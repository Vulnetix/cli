package com.shop.domain;

import jakarta.persistence.Embeddable;
import jakarta.persistence.Entity;

@jakarta.persistence.Embeddable
~>public class Address {
    private String street;
}

@Entity(name = "Order")
@SuppressWarnings({"unused",
    "serial"})
~>public final class PurchaseOrder
        implements Comparable<PurchaseOrder> {
    public int compareTo(PurchaseOrder o) { return 0; }
}
