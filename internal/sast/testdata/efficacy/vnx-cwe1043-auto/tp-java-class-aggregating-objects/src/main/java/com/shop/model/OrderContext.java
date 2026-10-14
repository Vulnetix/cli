package com.shop.model;

import java.util.List;
import java.util.Map;

~>public class OrderContext {

    private static final Logger LOG = LoggerFactory.getLogger(OrderContext.class);

    private final Customer customer;
    private Address billingAddress;
    private Address shippingAddress;
    private List<OrderLine> lines;
    private Map<String, Discount> discounts;
    private PaymentMethod paymentMethod;
    private Invoice invoice;
    @Nullable
    private Shipment shipment;
    protected Warehouse warehouse;
    private TaxPolicy taxPolicy;
    private AuditTrail audit;
    private Set<Coupon> coupons = new HashSet<>();
    private String note;
    private int version;

    public OrderContext(Customer customer) {
        this.customer = customer;
    }

    public Customer getCustomer() {
        return customer;
    }
}
