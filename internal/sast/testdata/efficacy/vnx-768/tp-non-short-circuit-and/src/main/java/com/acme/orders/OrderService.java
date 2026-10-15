package com.acme.orders;

public class OrderService {
    boolean canShip(Order order, Customer customer) {
~>        if (order != null & order.isPaid()) {
            return true;
        }
~>        if (null != customer & customer.getAddress() != null) {
            return true;
        }
~>        boolean ok = (order.items != null) & order.items.size() > 0;
        return ok;
    }
}
