package com.acme.orders;

public class SafeOrderService {
    public boolean canShip(Order order) {
        if (order != null && order.isPaid()) {
            return true;
        }
        return order == null || order.getItems().isEmpty();
    }
}
