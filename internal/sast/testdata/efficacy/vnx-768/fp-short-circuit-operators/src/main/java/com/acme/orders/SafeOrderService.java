package com.acme.orders;

public class SafeOrderService {
    boolean canShip(Order order, Customer customer) {
        if (order != null && order.isPaid()) {
            return true;
        }
        if (customer == null || customer.getAddress() == null) {
            return false;
        }
        return true;
    }
}
