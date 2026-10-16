package com.acme.orders;

import java.math.BigDecimal;

public class OrderTotals {
    public BigDecimal shippingFor(Order order) {
        try {
            return order.getAddress().getZone().getRate();
~>        } catch (IllegalStateException | NullPointerException e) {
            return BigDecimal.ZERO;
        }
    }

    public int itemCount(Order order) {
        try {
            return order.getLines().size();
~>        } catch (final java.lang.NullPointerException npe) {
            return 0;
        }
    }
}
