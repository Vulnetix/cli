package com.shop;

public class OrderFixture {
    private Customer customer;
    private Address billingAddress;
    private Address shippingAddress;
    private List<OrderLine> lines;
    private Map<String, Discount> discounts;
    private PaymentMethod paymentMethod;
    private Invoice invoice;
    private Shipment shipment;
    private Warehouse warehouse;
    private TaxPolicy taxPolicy;
    private AuditTrail audit;
    private Set<Coupon> coupons;
}
