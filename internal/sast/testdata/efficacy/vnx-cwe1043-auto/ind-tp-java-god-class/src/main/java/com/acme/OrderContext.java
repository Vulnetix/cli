package com.acme;

import java.util.List;
import java.util.Map;

~>public class OrderContext {
    private final Customer customer;
    private Address billingAddress;
    private Address shippingAddress;
    private List<OrderLine> lines;
    private Map<String, Discount> discounts;
    private PaymentMethod payment;
    private Warehouse warehouse;
    private Carrier carrier;
    private TaxPolicy taxPolicy;
    private InvoiceTemplate invoice;
    private Currency currency;
    private AuditTrail audit;
    private String note;
    private int quantity;

    public OrderContext(Customer customer) {
        this.customer = customer;
    }
}
